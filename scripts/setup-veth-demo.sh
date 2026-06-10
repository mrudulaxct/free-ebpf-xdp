#!/usr/bin/env bash
set -euo pipefail

VID="${VID:-100}"
NS1="${NS1:-pc1}"
NS2="${NS2:-pc2}"

cleanup() {
  ip netns del "$NS1" 2>/dev/null || true
  ip netns del "$NS2" 2>/dev/null || true
  ip link del pc1-a 2>/dev/null || true
  ip link del pc2-b 2>/dev/null || true
  ip link del ab0 2>/dev/null || true
  ip link del ab1 2>/dev/null || true
}

cleanup

ip netns add "$NS1"
ip netns add "$NS2"

ip link add pc1-a type veth peer name eth0 netns "$NS1"
ip link add pc2-b type veth peer name eth0 netns "$NS2"
ip link add ab0 type veth peer name ba0
ip link add ab1 type veth peer name ba1

ip link set pc1-a up
ip link set pc2-b up
ip link set ab0 up
ip link set ba0 up
ip link set ab1 up
ip link set ba1 up

ip netns exec "$NS1" ip link set lo up
ip netns exec "$NS1" ip link set eth0 up
ip netns exec "$NS2" ip link set lo up
ip netns exec "$NS2" ip link set eth0 up

ip netns exec "$NS1" ip link add link eth0 name eth0."$VID" type vlan id "$VID"
ip netns exec "$NS2" ip link add link eth0 name eth0."$VID" type vlan id "$VID"
ip netns exec "$NS1" ip link set eth0."$VID" up
ip netns exec "$NS2" ip link set eth0."$VID" up

ip netns exec "$NS1" ip addr add 10.0.0.1/24 dev eth0."$VID"
ip netns exec "$NS2" ip addr add 10.0.0.2/24 dev eth0."$VID"

echo "Demo topology created."
echo "Build with: make"
echo "Start all four FRER programs with: sudo ./scripts/run-veth-frer.sh"
echo
echo "Forward direction:"
echo "  sudo ./build/frerctl replicate --ingress pc1-a --egress ab0,ab1 --vid $VID"
echo "  sudo ./build/frerctl eliminate --ingress ba0,ba1 --egress pc2-b --vid $VID"
echo
echo "Return direction, needed for ping replies:"
echo "  sudo ./build/frerctl replicate --ingress pc2-b --egress ba0,ba1 --vid $VID"
echo "  sudo ./build/frerctl eliminate --ingress ab0,ab1 --egress pc1-a --vid $VID"
echo
echo "Ping through protected stream: sudo ip netns exec $NS1 ping -I eth0.$VID 10.0.0.2"
