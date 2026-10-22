#!/usr/bin/env bash
# tun-netns-e2e.sh — full host-networking end-to-end check for KronosMesh.
#
# Topology: two network namespaces (A and B), each linked to the host
# by its own veth pair; the host forwards between the links and runs
# the control plane. One daemon runs per namespace with TUN enabled.
# The check proves that a plain `ping` between the two VIRTUAL IPs
# crosses the encrypted mesh: the packet leaves A's kernel via its TUN
# device, travels the Noise tunnel over the veth links, and is
# delivered by B's kernel to its TUN address — no application-level
# tooling on the data path. A mesh-DNS lookup is verified the same way.
#
# Requirements: a real Linux host with root, iproute2, ping, and both
# binaries built:
#     (cd core/daemon && cargo build --release)
#     (cd control-plane && go build -o kronos-control-plane .)
#
# This script is NOT run by CI and was NOT run in the development
# sandbox: that sandbox forbids entering network namespaces (setns
# EPERM) and blocks userspace UDP sends outright, so a two-host test
# cannot execute there. It is written for verification on a normal
# Linux machine.
#
# Usage:  sudo ./scripts/tun-netns-e2e.sh
# Env:    DAEMON_BIN, CP_BIN override binary paths.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DAEMON="${DAEMON_BIN:-$ROOT_DIR/core/daemon/target/release/kronos-daemon}"
CP="${CP_BIN:-$ROOT_DIR/control-plane/kronos-control-plane}"
NS_A="kronos-a"
NS_B="kronos-b"
WORK="$(mktemp -d)"
ADMIN_TOKEN="e2e-admin-token-for-local-test-only"
CP_PID=""

cleanup() {
  set +e
  for ns in "$NS_A" "$NS_B"; do
    ip netns exec "$ns" pkill -INT kronos-daemon 2>/dev/null
  done
  sleep 1
  [ -n "$CP_PID" ] && kill "$CP_PID" 2>/dev/null
  ip netns del "$NS_A" 2>/dev/null
  ip netns del "$NS_B" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

for bin in "$DAEMON" "$CP"; do
  [ -x "$bin" ] || { echo "FAIL: $bin not built (see header)"; exit 1; }
done

echo "== namespaces + veth links (host forwards between them) =="
ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add veth-ha type veth peer name veth-a
ip link add veth-hb type veth peer name veth-b
ip link set veth-a netns "$NS_A"
ip link set veth-b netns "$NS_B"
ip addr add 10.99.1.1/24 dev veth-ha; ip link set veth-ha up
ip addr add 10.99.2.1/24 dev veth-hb; ip link set veth-hb up
ip netns exec "$NS_A" ip addr add 10.99.1.2/24 dev veth-a
ip netns exec "$NS_A" ip link set veth-a up
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_A" ip route add 10.99.2.0/24 via 10.99.1.1
ip netns exec "$NS_B" ip addr add 10.99.2.2/24 dev veth-b
ip netns exec "$NS_B" ip link set veth-b up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_B" ip route add 10.99.1.0/24 via 10.99.2.1
sysctl -qw net.ipv4.ip_forward=1

echo "== control plane on the host =="
KRONOS_ADMIN_TOKEN="$ADMIN_TOKEN" PORT=8080 "$CP" >"$WORK/cp.log" 2>&1 &
CP_PID=$!
sleep 1
curl -sf http://127.0.0.1:8080/api/v1/health >/dev/null || { echo "FAIL: control plane not healthy"; cat "$WORK/cp.log"; exit 1; }
# The mesh is default-deny: seed the allow rule the ping needs.
curl -sf -X POST http://127.0.0.1:8080/api/v1/acls \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"source_role":"*","dest_service":"*","port":0,"action":"ALLOW","priority":1}' >/dev/null
echo "control plane up, allow-all mesh-data rule seeded"

echo "== daemons with TUN on =="
ip netns exec "$NS_A" env \
  KRONOS_NODE_NAME=node-a KRONOS_ROLE=node \
  KRONOS_LISTEN_PORT=51871 \
  KRONOS_ADVERTISE_ENDPOINT="10.99.1.2:51871" \
  KRONOS_CONTROL_URL="http://10.99.1.1:8080" \
  KRONOS_CONTROL_TOKEN="$ADMIN_TOKEN" \
  KRONOS_ALLOW_INSECURE_HTTP=1 \
  KRONOS_TUN=1 KRONOS_STATE_DIR="$WORK/a" \
  "$DAEMON" up >"$WORK/a.log" 2>&1 &
ip netns exec "$NS_B" env \
  KRONOS_NODE_NAME=node-b KRONOS_ROLE=node \
  KRONOS_LISTEN_PORT=51872 \
  KRONOS_ADVERTISE_ENDPOINT="10.99.2.2:51872" \
  KRONOS_CONTROL_URL="http://10.99.2.1:8080" \
  KRONOS_CONTROL_TOKEN="$ADMIN_TOKEN" \
  KRONOS_ALLOW_INSECURE_HTTP=1 \
  KRONOS_TUN=1 KRONOS_STATE_DIR="$WORK/b" \
  "$DAEMON" up >"$WORK/b.log" 2>&1 &

sleep 3
grep -q "TUN interface kronos0 up" "$WORK/a.log" || { echo "FAIL: node A TUN not up"; cat "$WORK/a.log"; exit 1; }
grep -q "TUN interface kronos0 up" "$WORK/b.log" || { echo "FAIL: node B TUN not up"; cat "$WORK/b.log"; exit 1; }
VIP_A="$(grep -oE 'virtual 100\.[0-9.]+' "$WORK/a.log" | awk '{print $2}' | head -1)"
VIP_B="$(grep -oE 'virtual 100\.[0-9.]+' "$WORK/b.log" | awk '{print $2}' | head -1)"
echo "node A VIP: $VIP_A   node B VIP: $VIP_B"
[ -n "$VIP_A" ] && [ -n "$VIP_B" ] || { echo "FAIL: VIPs not found in logs"; exit 1; }

echo "== waiting for the mesh session + ACL sync, then ping =="
ok=0
for i in $(seq 1 30); do
  if ip netns exec "$NS_A" ping -c 1 -W 2 "$VIP_B" >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] || { echo "FAIL: ping never crossed the mesh"; tail -20 "$WORK/a.log" "$WORK/b.log"; exit 1; }
ip netns exec "$NS_A" ping -c 3 -W 2 "$VIP_B"
echo "PASS: ICMP crossed the encrypted mesh between host stacks"

echo "== mesh DNS from inside namespace A =="
if command -v python3 >/dev/null; then
  ip netns exec "$NS_A" python3 - "$VIP_A" "$VIP_B" <<'PYEOF'
import socket, struct, sys
vip_a, vip_b = sys.argv[1], sys.argv[2]
msg = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
for label in "node-b.mesh".split('.'):
    msg += bytes([len(label)]) + label.encode()
msg += b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
s.sendto(msg, (vip_a, 53))
data, _ = s.recvfrom(2048)
an = struct.unpack(">H", data[6:8])[0]
answer = ".".join(map(str, data[-4:]))
assert an >= 1 and answer == vip_b, f"unexpected answer: an={an} ip={answer}"
print(f"PASS: node-b.mesh resolved to {answer} via mesh DNS")
PYEOF
else
  echo "SKIP: python3 not available for the DNS check"
fi
echo "== ALL CHECKS PASSED =="
