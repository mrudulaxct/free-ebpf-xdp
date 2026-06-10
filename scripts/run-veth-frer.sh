#!/usr/bin/env bash
set -euo pipefail

VID="${VID:-100}"
LOG_DIR="${LOG_DIR:-/tmp/frer-ebpf-xdp}"

if [ ! -x ./build/frerctl ] || [ ! -f ./build/frer_kern.o ]; then
  echo "Build output missing. Run: make"
  exit 1
fi

mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log "$LOG_DIR"/pids

if [ "$(id -u)" -eq 0 ]; then
  RUN_AS_ROOT=()
else
  RUN_AS_ROOT=(sudo)
fi

start() {
  local name="$1"
  shift
  echo "Starting $name"
  "${RUN_AS_ROOT[@]}" ./build/frerctl "$@" --vid "$VID" >"$LOG_DIR/$name.log" 2>&1 &
  echo "$!" >> "$LOG_DIR/pids"
}

start fwd-replicate replicate --ingress pc1-a --egress ab0,ab1
start fwd-eliminate eliminate --ingress ba0,ba1 --egress pc2-b
start rev-replicate replicate --ingress pc2-b --egress ba0,ba1
start rev-eliminate eliminate --ingress ab0,ab1 --egress pc1-a

sleep 2

failed=0
while read -r pid; do
  if ! kill -0 "$pid" 2>/dev/null; then
    failed=1
  fi
done < "$LOG_DIR/pids"

if [ "$failed" -ne 0 ]; then
  echo "One or more FRER programs exited during startup."
  echo
  for log in "$LOG_DIR"/*.log; do
    echo "===== $log ====="
    cat "$log" || true
    echo
  done
  exit 1
fi

echo "FRER programs started."
echo "Logs: $LOG_DIR/*.log"
echo "Stop: sudo ./scripts/cleanup-veth-demo.sh"
