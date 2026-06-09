# Per-Packet Service Protection with Kernel-Level FRER

This project is a simple software-side implementation of the base paper, **"Lightweight Implementation of Per-packet Service Protection in eBPF/XDP"**, adapted for the project abstract **"Per-Packet Service Protection Using Kernel-Level FRER Implementation"**.

The base paper shows that FRER can run close to the NIC by using XDP instead of requiring a TSN switch chip or a fully hardware dataplane. This repository follows that idea: the realtime packet path is in eBPF/XDP, while userspace only configures BPF maps and reads counters.

## What the Base Paper Does

The paper implements IEEE 802.1CB FRER in two ways:

- **XDP FRER**: kernel-level eBPF/XDP packet processing.
- **uFRER**: userspace packet processing with raw sockets.

The important dataplane behavior is:

1. A stream is identified by header fields. In the paper implementation, VLAN ID is used.
2. The replication node adds an **R-tag** containing a monotonically increasing sequence number.
3. The same Ethernet frame is replicated to redundant paths.
4. The elimination node receives copies from those paths.
5. It forwards only the first packet with a sequence number and drops later duplicates.
6. Userspace communicates with the XDP program through BPF maps for configuration and statistics.

The paper's hardware-oriented idea is not that FRER requires hardware. It says hardware gives deterministic bounded cycles, but XDP gives a lightweight software implementation that runs early in the Linux RX path and avoids kernel modifications.

## What This Project Implements

This repository keeps the implementation simple and close to the paper:

- `src/frer_kern.c`: eBPF/XDP dataplane.
- `src/frerctl.c`: C userspace loader and map configurator.
- `scripts/setup-veth-demo.sh`: local Linux veth topology for testing two redundant paths.
- `scripts/cleanup-veth-demo.sh`: removes the demo topology.

Implemented features:

- VLAN-based stream classification.
- 6-byte FRER R-tag insertion after the VLAN tag.
- XDP devmap broadcast replication to two or more interfaces.
- Duplicate elimination using a 64-packet vector/history window.
- R-tag removal before forwarding the surviving frame.
- BPF maps for userspace/kernel communication.
- Realtime counters for received, replicated, passed, duplicate, malformed, and unconfigured packets.

## Ethernet Frame Layout

The protected frame follows the structure you provided:

```text
Destination MAC | Source MAC | VLAN Tag | R-TAG Seq No | EtherType | Payload
6 bytes         | 6 bytes    | 4 bytes  | 6 bytes      | 2 bytes   | IP packet
```

In code, the 6-byte R-tag is:

```c
struct rtag_hdr {
    __be16 reserved;
    __be16 seq;
    __be16 next_proto;
};
```

`next_proto` carries the original EtherType, usually IPv4 `0x0800` or IPv6 `0x86dd`. The VLAN encapsulated protocol is changed to `0xf1c1`, matching the paper's R-tag marker.

## BPF Maps

The project uses these maps:

- `stream_cfg`: keyed by VLAN ID. Enables a stream and stores the final egress interface for elimination.
- `seqgens`: keyed by VLAN ID. Stores the next sequence number for replication.
- `recovery`: keyed by VLAN ID. Stores the duplicate elimination state.
- `replica_ports`: XDP devmap containing redundant egress interfaces.
- `stats`: per-CPU counters read by userspace.

This is the kernel/userspace switch requested in the project: userspace writes configuration into maps, and XDP reads those maps at packet time.

## Requirements

Run this on Linux, not macOS. XDP/eBPF requires the Linux kernel.

Install dependencies on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y clang llvm make gcc libbpf-dev libelf-dev zlib1g-dev iproute2 tcpdump
```

Recommended kernel: Linux 5.12 or newer. The paper used Linux 6.2, but this code avoids unusual kernel features.

## Build

```bash
make
```

Expected outputs:

- `build/frer_kern.o`
- `build/frerctl`

## Run the Local Demo

Create a two-path software topology:

```bash
sudo ./scripts/setup-veth-demo.sh
```

The topology is:

```text
pc1 namespace -> pc1-a -> XDP replicate -> ab0/ab1
ab0 <-> ba0
ab1 <-> ba1
ba0/ba1 -> XDP eliminate -> pc2-b -> pc2 namespace
```

Attach FRER for traffic from PC1 to PC2:

```bash
sudo ./build/frerctl replicate --ingress pc1-a --egress ab0,ab1 --vid 100
sudo ./build/frerctl eliminate --ingress ba0,ba1 --egress pc2-b --vid 100
```

For `ping`, also protect the reply direction:

```bash
sudo ./build/frerctl replicate --ingress pc2-b --egress ba0,ba1 --vid 100
sudo ./build/frerctl eliminate --ingress ab0,ab1 --egress pc1-a --vid 100
```

Each command prints live counters once per second, so run them in separate terminals. For convenience, the repository also includes a helper that starts all four programs in the background:

```bash
sudo ./scripts/run-veth-frer.sh
tail -f /tmp/frer-ebpf-xdp/*.log
```

Test:

```bash
ping -I pc1-a.100 10.0.0.2
```

Simulate one path failure:

```bash
sudo ip link set ab0 down
```

The ping should continue through `ab1/ba1`.

Recover the path:

```bash
sudo ip link set ab0 up
```

Simulate total failure:

```bash
sudo ip link set ab0 down
sudo ip link set ab1 down
```

Now packets should stop because both redundant paths are down.

Cleanup:

```bash
sudo ./scripts/cleanup-veth-demo.sh
```

## Running on Real Interfaces

Use the same commands with physical interface names:

```bash
sudo ./build/frerctl replicate --ingress eth0 --egress eth1,eth2 --vid 100
sudo ./build/frerctl eliminate --ingress eth1,eth2 --egress eth0 --vid 100
```

If the NIC does not receive frames unless they are addressed to it, enable promiscuous mode:

```bash
sudo ip link set eth1 promisc on
sudo ip link set eth2 promisc on
```

This matches the paper's note that physical NICs may need promiscuous mode, while veth usually does not.

## How It Works

Replication path:

1. XDP receives a VLAN-tagged Ethernet frame.
2. It reads the VLAN ID and looks up that stream in `stream_cfg`.
3. It reads and increments the stream sequence number in `seqgens`.
4. It creates room after the VLAN tag with `bpf_xdp_adjust_head`.
5. It writes the 6-byte R-tag.
6. It broadcasts the frame through `replica_ports`.

Elimination path:

1. XDP receives a replicated frame from one redundant path.
2. It checks for VLAN protocol `0xf1c1`.
3. It reads the R-tag sequence number.
4. It removes the R-tag and restores the original EtherType.
5. It checks the sequence number in the recovery bitmap.
6. First arrival passes; duplicate arrivals drop.
7. The surviving packet is redirected to the final egress interface.

## Scope and Limitations

This is a clear working baseline, not a full IEEE 802.1CB production stack.

Kept simple intentionally:

- Stream matching is VLAN ID only.
- One `replica_ports` devmap is used per loaded replication instance.
- The recovery window is 64 sequence numbers.
- The userspace control plane is CLI-based, not a GUI dashboard.
- Monitoring is terminal counters; the abstract's visualization/dashboard can be added on top later.

The core FRER behavior from the paper is present: sequence generation, R-tag encapsulation, frame replication, duplicate elimination, map-based control, and XDP kernel-level execution.
