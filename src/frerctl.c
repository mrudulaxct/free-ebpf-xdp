// SPDX-License-Identifier: MIT
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

struct stream_cfg {
	__u32 enabled;
	__u32 recovery_timeout_ns;
	__u32 egress_ifindex;
	__u32 vlan_id;
};

struct seq_gen {
	__u32 lock;
	__u16 next_seq;
};

struct recovery_state {
	__u32 lock;
	__u16 base_seq;
	__u64 seen_bitmap;
	__u64 last_seen_ns;
	__u32 initialized;
};

struct frer_stats {
	__u64 rx;
	__u64 replicated;
	__u64 passed;
	__u64 duplicates;
	__u64 malformed;
	__u64 no_config;
};

static volatile sig_atomic_t exiting;

static void on_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s replicate --obj build/frer_kern.o --ingress IF --egress IF1,IF2 --vid 100\n"
		"  %s eliminate --obj build/frer_kern.o --ingress IF1,IF2 --egress IF --vid 100\n"
		"  %s detach --ingress IF1,IF2\n\n"
		"Options:\n"
		"  --timeout-ms N   Recovery reset timeout, default 2000 ms\n",
		prog, prog, prog);
}

static int bump_memlock(void)
{
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
	return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static int ifindex_or_die(const char *name)
{
	unsigned int idx = if_nametoindex(name);
	if (!idx) {
		fprintf(stderr, "Unknown interface %s\n", name);
		exit(1);
	}
	return (int)idx;
}

static int split_csv(char *csv, char **items, int max_items)
{
	int n = 0;
	char *tok;

	while ((tok = strsep(&csv, ",")) != NULL) {
		if (!*tok)
			continue;
		if (n == max_items)
			break;
		items[n++] = tok;
	}
	return n;
}

static int find_map_fd(struct bpf_object *obj, const char *name)
{
	struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
	if (!map) {
		fprintf(stderr, "Map not found: %s\n", name);
		return -1;
	}
	return bpf_map__fd(map);
}

static int attach_one(struct bpf_program *prog, const char *ifname)
{
	int ifindex = ifindex_or_die(ifname);
	struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
	char pin_path[256];
	int err;

	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "Attach failed on %s: %s\n", ifname, strerror(-err));
		return err;
	}

	snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/frer_%s", ifname);
	unlink(pin_path);
	err = bpf_link__pin(link, pin_path);
	if (err) {
		fprintf(stderr, "Pin link failed at %s: %s\n", pin_path, strerror(-err));
		bpf_link__destroy(link);
		return err;
	}

	printf("attached %s and pinned %s\n", ifname, pin_path);
	return 0;
}

static void print_stats(int stats_fd)
{
	__u32 key = 0;
	unsigned int ncpu = libbpf_num_possible_cpus();
	struct frer_stats *values = calloc(ncpu, sizeof(*values));
	struct frer_stats total = {};

	if (!values)
		return;
	if (bpf_map_lookup_elem(stats_fd, &key, values) != 0) {
		free(values);
		return;
	}

	for (unsigned int i = 0; i < ncpu; i++) {
		total.rx += values[i].rx;
		total.replicated += values[i].replicated;
		total.passed += values[i].passed;
		total.duplicates += values[i].duplicates;
		total.malformed += values[i].malformed;
		total.no_config += values[i].no_config;
	}

	printf("rx=%llu replicated=%llu passed=%llu duplicates=%llu malformed=%llu no_config=%llu\n",
	       total.rx, total.replicated, total.passed, total.duplicates,
	       total.malformed, total.no_config);
	free(values);
}

int main(int argc, char **argv)
{
	int err;
	const char *prog_path = argv[0];
	const char *mode, *obj_path = "build/frer_kern.o";
	char *ingress_csv = NULL, *egress_csv = NULL;
	char *ingress_items[16], *egress_items[16];
	int ingress_count, egress_count;
	__u32 vid = 100, timeout_ms = 2000;

	static const struct option long_opts[] = {
		{"obj", required_argument, NULL, 'o'},
		{"ingress", required_argument, NULL, 'i'},
		{"egress", required_argument, NULL, 'e'},
		{"vid", required_argument, NULL, 'v'},
		{"timeout-ms", required_argument, NULL, 't'},
		{0, 0, 0, 0},
	};

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	mode = argv[1];
	argc--;
	argv++;

	int opt;
	while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'o':
			obj_path = optarg;
			break;
		case 'i':
			ingress_csv = strdup(optarg);
			break;
		case 'e':
			egress_csv = strdup(optarg);
			break;
		case 'v':
			vid = (__u32)strtoul(optarg, NULL, 0);
			break;
		case 't':
			timeout_ms = (__u32)strtoul(optarg, NULL, 0);
			break;
		default:
			usage(prog_path);
			return 1;
		}
	}

	if (!strcmp(mode, "detach")) {
		if (!ingress_csv) {
			usage(prog_path);
			return 1;
		}
		ingress_count = split_csv(ingress_csv, ingress_items, 16);
		for (int i = 0; i < ingress_count; i++) {
			char pin_path[256];
			snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/frer_%s",
				 ingress_items[i]);
			unlink(pin_path);
			bpf_xdp_detach(ifindex_or_die(ingress_items[i]), 0, NULL);
			printf("detached %s\n", ingress_items[i]);
		}
		return 0;
	}

	if (!ingress_csv || !egress_csv ||
	    (strcmp(mode, "replicate") && strcmp(mode, "eliminate"))) {
		usage(prog_path);
		return 1;
	}

	if (bump_memlock())
		perror("setrlimit(RLIMIT_MEMLOCK)");

	ingress_count = split_csv(ingress_csv, ingress_items, 16);
	egress_count = split_csv(egress_csv, egress_items, 16);

	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "Cannot open %s: %s\n", obj_path, strerror(-err));
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "Cannot load BPF object: %s\n", strerror(-err));
		return 1;
	}

	int cfg_fd = find_map_fd(obj, "stream_cfg");
	int seq_fd = find_map_fd(obj, "seqgens");
	int rec_fd = find_map_fd(obj, "recovery");
	int devmap_fd = find_map_fd(obj, "replica_ports");
	int stats_fd = find_map_fd(obj, "stats");
	if (cfg_fd < 0 || seq_fd < 0 || rec_fd < 0 || devmap_fd < 0 || stats_fd < 0)
		return 1;

	struct stream_cfg cfg = {
		.enabled = 1,
		.recovery_timeout_ns = timeout_ms * 1000U * 1000U,
		.egress_ifindex = 0,
		.vlan_id = vid,
	};
	if (!strcmp(mode, "eliminate"))
		cfg.egress_ifindex = ifindex_or_die(egress_items[0]);

	struct seq_gen gen = {};
	struct recovery_state rec = {};
	__u32 default_key = 0;

	bpf_map_update_elem(cfg_fd, &vid, &cfg, BPF_ANY);
	bpf_map_update_elem(seq_fd, &vid, &gen, BPF_ANY);
	bpf_map_update_elem(rec_fd, &vid, &rec, BPF_ANY);
	bpf_map_update_elem(cfg_fd, &default_key, &cfg, BPF_ANY);
	bpf_map_update_elem(seq_fd, &default_key, &gen, BPF_ANY);

	if (!strcmp(mode, "replicate")) {
		for (int i = 0; i < egress_count; i++) {
			__u32 key = i;
			__u32 ifindex = ifindex_or_die(egress_items[i]);
			bpf_map_update_elem(devmap_fd, &key, &ifindex, BPF_ANY);
			printf("replica port %d -> %s(ifindex=%u)\n",
			       i, egress_items[i], ifindex);
		}
	}

	const char *prog_name = !strcmp(mode, "replicate") ?
		"xdp_replicate" : "xdp_eliminate";
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "Program not found: %s\n", prog_name);
		return 1;
	}

	for (int i = 0; i < ingress_count; i++) {
		err = attach_one(prog, ingress_items[i]);
		if (err)
			return 1;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	printf("FRER %s is running for VLAN %u. Press Ctrl-C to stop stats loop; pinned links remain active.\n",
	       mode, vid);
	while (!exiting) {
		sleep(1);
		print_stats(stats_fd);
	}

	bpf_object__close(obj);
	return 0;
}
