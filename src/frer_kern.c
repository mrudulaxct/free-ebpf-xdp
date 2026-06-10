// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal IEEE 802.1CB-style FRER dataplane for XDP.
 *
 * The implementation follows the paper's software design:
 * - identify protected streams by VLAN ID
 * - insert a 6-byte redundancy tag carrying the sequence number
 * - replicate frames with a devmap broadcast
 * - eliminate duplicate replicas with a vector recovery window
 * - expose configuration and counters through BPF maps
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK 0x0FFF
#endif

#ifndef __VMLINUX_H__

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#endif

#define ETH_SIZE 14
#define VLAN_SIZE 4
#define RTAG_SIZE 6
#define VLAN_RTAG_SIZE (VLAN_SIZE + RTAG_SIZE)
#define FRER_RTAG_ETHERTYPE 0xf1c1
#define FRER_WINDOW_SIZE 64

struct rtag_hdr {
	__be16 reserved;
	__be16 seq;
	__be16 next_proto;
} __attribute__((packed));

struct stream_cfg {
	__u32 enabled;
	__u32 recovery_timeout_ns;
	__u32 egress_ifindex;
	__u32 vlan_id;
};

struct seq_gen {
	struct bpf_spin_lock lock;
	__u16 next_seq;
};

struct recovery_state {
	struct bpf_spin_lock lock;
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct stream_cfg);
} stream_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct seq_gen);
} seqgens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct recovery_state);
} recovery SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u32);
} replica_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct frer_stats);
} stats SEC(".maps");

static __always_inline struct frer_stats *get_stats(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline int parse_vlan(void *data, void *data_end,
				      struct ethhdr **eth,
				      struct vlan_hdr **vlan)
{
	if (data + ETH_SIZE + VLAN_SIZE > data_end)
		return -1;

	*eth = data;
	if ((*eth)->h_proto != bpf_htons(ETH_P_8021Q) &&
	    (*eth)->h_proto != bpf_htons(ETH_P_8021AD))
		return -2;

	*vlan = data + ETH_SIZE;
	return 0;
}

static __always_inline __u32 vlan_id(const struct vlan_hdr *vlan)
{
	return bpf_ntohs(vlan->h_vlan_TCI) & VLAN_VID_MASK;
}

static __always_inline int add_rtag(struct xdp_md *ctx, __u16 seq)
{
	void *old_data = (void *)(long)ctx->data;
	void *old_end = (void *)(long)ctx->data_end;

	if (old_data + ETH_SIZE + VLAN_SIZE > old_end)
		return -1;

	if (bpf_xdp_adjust_head(ctx, 0 - RTAG_SIZE))
		return -1;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	if (data + ETH_SIZE + VLAN_SIZE + RTAG_SIZE > data_end)
		return -1;

	__builtin_memmove(data, data + RTAG_SIZE, ETH_SIZE + VLAN_SIZE);

	struct vlan_hdr *vlan = data + ETH_SIZE;
	struct rtag_hdr *rtag = data + ETH_SIZE + VLAN_SIZE;
	__be16 original_proto = vlan->h_vlan_encapsulated_proto;

	__builtin_memset(rtag, 0, sizeof(*rtag));
	rtag->seq = bpf_htons(seq);
	rtag->next_proto = original_proto;
	vlan->h_vlan_encapsulated_proto = bpf_htons(FRER_RTAG_ETHERTYPE);
	return 0;
}

static __always_inline int add_vlan_rtag(struct xdp_md *ctx, __u16 seq,
					 __u32 vid)
{
	void *old_data = (void *)(long)ctx->data;
	void *old_end = (void *)(long)ctx->data_end;

	if (old_data + ETH_SIZE > old_end)
		return -1;

	__be16 original_proto = ((struct ethhdr *)old_data)->h_proto;

	if (bpf_xdp_adjust_head(ctx, 0 - VLAN_RTAG_SIZE))
		return -1;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	if (data + ETH_SIZE + VLAN_RTAG_SIZE > data_end)
		return -1;

	__builtin_memmove(data, data + VLAN_RTAG_SIZE, ETH_SIZE);

	struct ethhdr *eth = data;
	struct vlan_hdr *vlan = data + ETH_SIZE;
	struct rtag_hdr *rtag = data + ETH_SIZE + VLAN_SIZE;

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	vlan->h_vlan_TCI = bpf_htons(vid & VLAN_VID_MASK);
	vlan->h_vlan_encapsulated_proto = bpf_htons(FRER_RTAG_ETHERTYPE);

	__builtin_memset(rtag, 0, sizeof(*rtag));
	rtag->seq = bpf_htons(seq);
	rtag->next_proto = original_proto;
	return 0;
}

static __always_inline int remove_rtag(struct xdp_md *ctx, __u16 *seq)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	if (data + ETH_SIZE + VLAN_SIZE + RTAG_SIZE > data_end)
		return -1;

	struct vlan_hdr *vlan = data + ETH_SIZE;
	if (vlan->h_vlan_encapsulated_proto != bpf_htons(FRER_RTAG_ETHERTYPE))
		return -1;

	struct rtag_hdr *rtag = data + ETH_SIZE + VLAN_SIZE;
	*seq = bpf_ntohs(rtag->seq);
	vlan->h_vlan_encapsulated_proto = rtag->next_proto;

	__builtin_memmove(data + RTAG_SIZE, data, ETH_SIZE + VLAN_SIZE);
	if (bpf_xdp_adjust_head(ctx, RTAG_SIZE))
		return -1;

	return 0;
}

static __always_inline int seq_after(__u16 a, __u16 b)
{
	return (__s16)(a - b) > 0;
}

static __always_inline int recover_packet(struct recovery_state *rec,
					  __u16 seq, __u32 timeout_ns,
					  __u64 now)
{
	if (!rec->initialized ||
	    (timeout_ns && rec->last_seen_ns &&
	     now - rec->last_seen_ns > timeout_ns)) {
		rec->initialized = 1;
		rec->base_seq = seq;
		rec->seen_bitmap = 1ULL;
		rec->last_seen_ns = now;
		return 1;
	}

	if (seq_after(seq, rec->base_seq)) {
		__u16 shift = seq - rec->base_seq;

		if (shift >= FRER_WINDOW_SIZE)
			rec->seen_bitmap = 0;
		else
			rec->seen_bitmap <<= shift;

		rec->base_seq = seq;
		rec->seen_bitmap |= 1ULL;
		rec->last_seen_ns = now;
		return 1;
	}

	__u16 offset = rec->base_seq - seq;
	if (offset >= FRER_WINDOW_SIZE) {
		rec->last_seen_ns = now;
		return 0;
	}

	__u64 bit = 1ULL << offset;
	if (rec->seen_bitmap & bit) {
		rec->last_seen_ns = now;
		return 0;
	}

	rec->seen_bitmap |= bit;
	rec->last_seen_ns = now;
	return 1;
}

SEC("xdp")
int xdp_replicate(struct xdp_md *ctx)
{
	struct frer_stats *s = get_stats();
	if (s)
		s->rx++;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct vlan_hdr *vlan;
	int parse_result;
	__u32 cfg_key;

	parse_result = parse_vlan(data, data_end, &eth, &vlan);
	if (parse_result == -1) {
		if (s)
			s->malformed++;
		return XDP_PASS;
	}

	__u32 vid = 0;
	if (parse_result == 0)
		vid = vlan_id(vlan);
	cfg_key = vid;

	struct stream_cfg *cfg = bpf_map_lookup_elem(&stream_cfg, &vid);
	struct seq_gen *gen = bpf_map_lookup_elem(&seqgens, &vid);
	if (!cfg || !cfg->enabled || !gen) {
		cfg_key = 0;
		cfg = bpf_map_lookup_elem(&stream_cfg, &cfg_key);
		gen = bpf_map_lookup_elem(&seqgens, &cfg_key);
	}
	if (!cfg || !cfg->enabled || !gen) {
		if (s)
			s->no_config++;
		return XDP_PASS;
	}

	if (parse_result == -2) {
		__u16 seq;

		bpf_spin_lock(&gen->lock);
		seq = gen->next_seq++;
		bpf_spin_unlock(&gen->lock);

		if (add_vlan_rtag(ctx, seq, cfg->vlan_id) < 0) {
			if (s)
				s->malformed++;
			return XDP_DROP;
		}
	} else if (vlan->h_vlan_encapsulated_proto != bpf_htons(FRER_RTAG_ETHERTYPE)) {
		__u16 seq;

		bpf_spin_lock(&gen->lock);
		seq = gen->next_seq++;
		bpf_spin_unlock(&gen->lock);

		if (parse_result == 0 && add_rtag(ctx, seq) < 0) {
			if (s)
				s->malformed++;
			return XDP_DROP;
		}
	}

	if (s)
		s->replicated++;

	return bpf_redirect_map(&replica_ports, 0,
				BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
}

SEC("xdp")
int xdp_eliminate(struct xdp_md *ctx)
{
	struct frer_stats *s = get_stats();
	if (s)
		s->rx++;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct vlan_hdr *vlan;
	int parse_result;

	parse_result = parse_vlan(data, data_end, &eth, &vlan);
	if (parse_result < 0) {
		if (s)
			s->malformed += parse_result == -1;
		return XDP_PASS;
	}

	__u32 vid = vlan_id(vlan);
	struct stream_cfg *cfg = bpf_map_lookup_elem(&stream_cfg, &vid);
	struct recovery_state *rec = bpf_map_lookup_elem(&recovery, &vid);
	if (!cfg || !cfg->enabled || !rec) {
		if (s)
			s->no_config++;
		return XDP_PASS;
	}

	__u16 seq;
	if (remove_rtag(ctx, &seq) < 0) {
		if (s)
			s->malformed++;
		return XDP_DROP;
	}

	int pass;
	__u64 now = bpf_ktime_get_ns();
	bpf_spin_lock(&rec->lock);
	pass = recover_packet(rec, seq, cfg->recovery_timeout_ns, now);
	bpf_spin_unlock(&rec->lock);

	if (!pass) {
		if (s)
			s->duplicates++;
		return XDP_DROP;
	}

	if (s)
		s->passed++;

	if (cfg->egress_ifindex)
		return bpf_redirect(cfg->egress_ifindex, 0);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
