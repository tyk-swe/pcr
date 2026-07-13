#!/usr/bin/env bash
set -euo pipefail

binary=${1:-target/release/packetcraftr}
namespace=packetcraftr-peer
host_if=pcr-host
peer_if=pcr-peer
work=${TMPDIR:-/tmp}/packetcraftr-netns-$$

cleanup() {
  set +e
  ip netns pids "$namespace" | xargs -r kill
  ip netns del "$namespace"
  ip link del "$host_if"
  rm -rf "$work"
}
trap cleanup EXIT

test "$(id -u)" -eq 0
test -x "$binary"
mkdir -p "$work"
ip netns add "$namespace"
ip link add "$host_if" type veth peer name "$peer_if"
ip link set "$peer_if" netns "$namespace"
ip address add 10.203.0.1/24 dev "$host_if"
ip link set "$host_if" up
ethtool -K "$host_if" tx off rx off tso off gso off gro off >/dev/null
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip address add 10.203.0.2/24 dev "$peer_if"
ip netns exec "$namespace" ip link set "$peer_if" up
ip netns exec "$namespace" ethtool -K "$peer_if" tx off rx off tso off gso off gro off >/dev/null
sleep 1

# Passive readiness and the explicit probe must not change the interface's
# transmission counter.
tx_before=$(<"/sys/class/net/$host_if/statistics/tx_packets")
"$binary" --output json doctor --interface "$host_if" \
  --require interfaces,routes,layer2,layer3 >"$work/doctor.json"
jq -e '.status == "success" and .result.capture_probe_attempted == false' "$work/doctor.json" >/dev/null
"$binary" --output json doctor --interface "$host_if" --probe-capture \
  --require capture >"$work/doctor-probe.json"
tx_after=$(<"/sys/class/net/$host_if/statistics/tx_packets")
test "$tx_before" -eq "$tx_after"
jq -e '.result.capabilities[] | select(.name == "capture" and .status == "ready")' \
  "$work/doctor-probe.json" >/dev/null

# A custom BPF must admit related ICMP and reject unrelated UDP traffic.
"$binary" --output ndjson capture \
  --packet 'ipv4(src=10.203.0.1,dst=10.203.0.2)/udp(sport=40000,dport=9)/raw(hex="00")' \
  --interface "$host_if" --capture-mode host-only --capture-filter icmp \
  --timeout-ms 1800 >"$work/filtered.ndjson" &
capture_pid=$!
sleep 1
printf unrelated | ip netns exec "$namespace" socat - UDP4-DATAGRAM:10.203.0.1:65000 || true
ping -q -c 1 -W 1 10.203.0.2 >/dev/null
wait "$capture_pid"
grep -q '"record":"item"' "$work/filtered.ndjson"
grep -q '"event":"frame"' "$work/filtered.ndjson"

# A one-frame queue under an isolated ICMP flood must report loss without
# exceeding its configured memory bound or converting loss into silent success.
"$binary" --output ndjson capture \
  --packet 'ipv4(src=10.203.0.1,dst=10.203.0.2)/udp(sport=40000,dport=9)/raw(hex="00")' \
  --interface "$host_if" --capture-mode host-only --capture-filter icmp \
  --max-queue-frames 1 --max-captured-bytes 128 --snap-length 128 \
  --overflow-policy drop-newest --timeout-ms 2000 >"$work/queue-loss.ndjson" &
capture_pid=$!
sleep 1
ip netns exec "$namespace" ping -q -f -c 20000 -W 1 10.203.0.1 >/dev/null
wait "$capture_pid"
tail -n 1 "$work/queue-loss.ndjson" | jq -e '
  .record == "complete"
  and (.stats.capture.overflow_events | tonumber) > 0
  and any(.diagnostics[]; .code == "capture.evidence_incomplete")
' >/dev/null

# Promiscuous mode is visible while armed, removed after cancellation, and
# cancellation plus capture-worker cleanup completes within one second for
# both supported Unix termination signals.
assert_signal_cleanup() {
  signal=$1
  expected_status=$2
  label=$3
  "$binary" --output ndjson capture \
    --packet 'ipv4(src=10.203.0.1,dst=10.203.0.2)/udp(sport=40000,dport=9)/raw(hex="00")' \
    --interface "$host_if" --capture-filter icmp --timeout-ms 30000 \
    >"$work/cancel-$label.ndjson" &
  capture_pid=$!
  for _ in $(seq 1 20); do
    if ip -details link show "$host_if" | grep -q 'promiscuity 1'; then
      break
    fi
    sleep 0.05
  done
  ip -details link show "$host_if" | grep -q 'promiscuity 1'
  cancel_started=$(date +%s%N)
  kill -"$signal" "$capture_pid"
  set +e
  wait "$capture_pid"
  cancel_status=$?
  set -e
  cancel_elapsed_ms=$((($(date +%s%N) - cancel_started) / 1000000))
  test "$cancel_status" -eq "$expected_status"
  test "$cancel_elapsed_ms" -lt 1000
  ip -details link show "$host_if" | grep -q 'promiscuity 0'
  tail -n 1 "$work/cancel-$label.ndjson" | \
    jq -e '.record == "cancelled" and .status == "cancelled"' >/dev/null
}

assert_signal_cleanup INT 130 sigint
assert_signal_cleanup TERM 143 sigterm

# A complete late-invalid replay preflight must send no frame.
python3 - "$work/late-invalid.pcap" <<'PY'
import socket
import struct
import sys

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff

source = socket.inet_aton("10.203.0.1")
destination = socket.inet_aton("10.203.0.2")
icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
icmp = struct.pack("!BBHHH", 8, 0, checksum(icmp), 1, 1)
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, source, destination)
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, checksum(ip), source, destination)
frame = ip + icmp
with open(sys.argv[1], "wb") as output:
    output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
    output.write(struct.pack("<IIII", 1, 0, len(frame), len(frame)))
    output.write(frame)
    output.write(bytes(8))
PY
tx_before=$(<"/sys/class/net/$host_if/statistics/tx_packets")
set +e
"$binary" --output json replay "$work/late-invalid.pcap" \
  --interface "$host_if" --link-mode layer3 --timing immediate \
  >"$work/replay.json"
replay_status=$?
set -e
tx_after=$(<"/sys/class/net/$host_if/statistics/tx_packets")
test "$replay_status" -ne 0
test "$tx_before" -eq "$tx_after"

# Real TCP, DNS, and traceroute response correlation on the isolated veth.
ip netns exec "$namespace" socat TCP4-LISTEN:8080,reuseaddr,fork EXEC:/bin/cat &
tcp_pid=$!
ip netns exec "$namespace" python3 -c '
import socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("10.203.0.2", 8081))
while True:
    _, peer = server.recvfrom(65535)
    server.sendto(b"packetcraftr-udp-response", peer)
' &
udp_pid=$!
ip netns exec "$namespace" dnsmasq --no-daemon --no-resolv --bind-interfaces \
  --listen-address=10.203.0.2 --address=/qual.test/10.203.0.2 &
dns_pid=$!
sleep 1
"$binary" --output json scan 10.203.0.2 --transport tcp --ports 8080 \
  --attempts 1 --batch-size 1 --rate 10 --timeout-ms 1000 \
  --interface "$host_if" --capture-mode host-only --auto-filter >"$work/scan.json"
jq -e '.status == "success" and any(.result.ports[]; .classification == "open")' \
  "$work/scan.json" >/dev/null
"$binary" --output json scan 10.203.0.2 --transport udp --ports 8081 \
  --attempts 1 --batch-size 1 --rate 10 --timeout-ms 1000 \
  --interface "$host_if" --capture-mode host-only --auto-filter >"$work/scan-udp.json"
jq -e '.status == "success" and any(.result.ports[]; .classification == "open")' \
  "$work/scan-udp.json" >/dev/null
"$binary" --output json dns 10.203.0.2 qual.test --attempts 1 --rate 10 \
  --timeout-ms 1000 --interface "$host_if" --capture-mode host-only --auto-filter \
  >"$work/dns.json"
jq -e '.status == "success" and .result.outcome == "response"' "$work/dns.json" >/dev/null
"$binary" --output json traceroute 10.203.0.2 --max-hops 2 --attempts 1 \
  --rate 10 --timeout-ms 1000 --interface "$host_if" \
  --capture-mode host-only --auto-filter >"$work/traceroute.json"
jq -e '.status == "success" and .result.completion == "destination_reached"' \
  "$work/traceroute.json" >/dev/null
kill "$tcp_pid" "$udp_pid" "$dns_pid" 2>/dev/null || true

# Two processes can independently arm and close filtered capture probes.
"$binary" --output json doctor --interface "$host_if" --probe-capture >"$work/concurrent-a.json" &
first=$!
"$binary" --output json doctor --interface "$host_if" --probe-capture >"$work/concurrent-b.json" &
second=$!
wait "$first"
wait "$second"

echo "native namespace qualification passed"
