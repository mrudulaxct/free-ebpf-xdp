#!/usr/bin/env bash
set -euo pipefail

NS1="${NS1:-pc1}"
NS2="${NS2:-pc2}"
LOG_DIR="${LOG_DIR:-/tmp/frer-ebpf-xdp}"

if [ -f "$LOG_DIR/pids" ]; then
  while read -r pid; do
    kill "$pid" 2>/dev/null || true
  done < "$LOG_DIR/pids"
  rm -f "$LOG_DIR/pids"
fi

ip netns del "$NS1" 2>/dev/null || true
ip netns del "$NS2" 2>/dev/null || true
ip link del pc1-a 2>/dev/null || true
ip link del pc2-b 2>/dev/null || true
ip link del ab0 2>/dev/null || true
ip link del ab1 2>/dev/null || true
rm -f /sys/fs/bpf/frer_* 2>/dev/null || true

echo "FRER demo topology removed."
