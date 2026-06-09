#!/usr/bin/env bash
set -euo pipefail

VID="${VID:-100}"
LOG_DIR="${LOG_DIR:-/tmp/frer-ebpf-xdp}"

mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log "$LOG_DIR"/pids

start() {
  local name="$1"
  shift
  echo "Starting $name"
  sudo ./build/frerctl "$@" --vid "$VID" >"$LOG_DIR/$name.log" 2>&1 &
  echo "$!" >> "$LOG_DIR/pids"
}

start fwd-replicate replicate --ingress pc1-a --egress ab0,ab1
start fwd-eliminate eliminate --ingress ba0,ba1 --egress pc2-b
start rev-replicate replicate --ingress pc2-b --egress ba0,ba1
start rev-eliminate eliminate --ingress ab0,ab1 --egress pc1-a

echo "FRER programs started."
echo "Logs: $LOG_DIR/*.log"
echo "Stop: sudo ./scripts/cleanup-veth-demo.sh"
