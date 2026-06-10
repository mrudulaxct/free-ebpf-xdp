#!/usr/bin/env bash
set -euo pipefail

VID="${VID:-100}"
LOG_DIR="${LOG_DIR:-/tmp/frer-ebpf-xdp}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo ./scripts/demo-smoke-test.sh"
  exit 1
fi

cleanup() {
  ./scripts/cleanup-veth-demo.sh >/dev/null 2>&1 || true
}

fail() {
  echo "FAIL: $*"
  echo
  echo "FRER logs:"
  for log in "$LOG_DIR"/*.log; do
    [ -f "$log" ] || continue
    echo "===== $log ====="
    tail -40 "$log"
  done
  cleanup
  exit 1
}

latest_value() {
  local log="$1"
  local key="$2"
  awk -v key="$key" '
    {
      for (i = 1; i <= NF; i++) {
        split($i, kv, "=")
        if (kv[1] == key) value = kv[2]
      }
    }
    END { print value + 0 }
  ' "$log"
}

echo "Resetting demo..."
cleanup

echo "Building..."
make clean >/dev/null
make

echo "Creating topology..."
./scripts/setup-veth-demo.sh

echo "Attaching FRER..."
./scripts/run-veth-frer.sh

echo "Sending protected traffic..."
if ! ip netns exec pc1 ping -I "eth0.$VID" -c 8 10.0.0.2; then
  fail "ping through FRER path failed"
fi

sleep 2

fwd_rep="$LOG_DIR/fwd-replicate.log"
fwd_elim="$LOG_DIR/fwd-eliminate.log"
rev_rep="$LOG_DIR/rev-replicate.log"
rev_elim="$LOG_DIR/rev-eliminate.log"

for log in "$fwd_rep" "$fwd_elim" "$rev_rep" "$rev_elim"; do
  [ -s "$log" ] || fail "$log is empty"
done

fwd_replicated=$(latest_value "$fwd_rep" replicated)
fwd_passed=$(latest_value "$fwd_elim" passed)
fwd_duplicates=$(latest_value "$fwd_elim" duplicates)
rev_replicated=$(latest_value "$rev_rep" replicated)
rev_passed=$(latest_value "$rev_elim" passed)
rev_duplicates=$(latest_value "$rev_elim" duplicates)

[ "$fwd_replicated" -gt 0 ] || fail "forward replicated counter stayed zero"
[ "$fwd_passed" -gt 0 ] || fail "forward passed counter stayed zero"
[ "$fwd_duplicates" -gt 0 ] || fail "forward duplicate counter stayed zero"
[ "$rev_replicated" -gt 0 ] || fail "return replicated counter stayed zero"
[ "$rev_passed" -gt 0 ] || fail "return passed counter stayed zero"
[ "$rev_duplicates" -gt 0 ] || fail "return duplicate counter stayed zero"

echo
echo "PASS: FRER demo is working"
echo "Forward: replicated=$fwd_replicated passed=$fwd_passed duplicates=$fwd_duplicates"
echo "Return:  replicated=$rev_replicated passed=$rev_passed duplicates=$rev_duplicates"
echo
echo "Leaving demo running for dashboard inspection."
