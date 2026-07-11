#!/usr/bin/env bash
set -euo pipefail

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

usage() {
    cat >&2 <<'EOF'
usage: scripts/qualify-linux-live.sh \
  (--archive PATH [--checksums PATH] | --workspace PATH) \
  --evidence DIRECTORY [--bundle PATH] [--expected-commit SHA] [--allow-dirty]

Runs the privileged Linux release-qualification matrix in disposable network
namespaces. A release/candidate archive is required for sign-off; --workspace
is intended only for developing the harness and requires a clean Git tree.
EOF
}

archive=""
checksums=""
workspace=""
evidence=""
bundle=""
expected_commit=""
allow_dirty=0
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --archive)
            archive="${2:-}"
            shift 2
            ;;
        --checksums)
            checksums="${2:-}"
            shift 2
            ;;
        --workspace)
            workspace="${2:-}"
            shift 2
            ;;
        --evidence)
            evidence="${2:-}"
            shift 2
            ;;
        --bundle)
            bundle="${2:-}"
            shift 2
            ;;
        --expected-commit)
            expected_commit="${2:-}"
            shift 2
            ;;
        --allow-dirty)
            allow_dirty=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [[ -z "${evidence}" ]] || [[ -n "${archive}" && -n "${workspace}" ]] ||
    [[ -z "${archive}" && -z "${workspace}" ]]; then
    usage
    exit 2
fi

root="$(git rev-parse --show-toplevel)"
script_directory="${root}/scripts"
tooling_commit="$(git -C "${root}" rev-parse HEAD)"
for command in \
    cargo ethtool find grep ip ldconfig ping python3 realpath rustc seq setpriv \
    sha256sum ss sudo sysctl tar tcpdump timeout xargs; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "required qualification command is unavailable: ${command}" >&2
        exit 1
    fi
done
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
    echo "Linux x86_64 is required for this qualification harness" >&2
    exit 1
fi
sudo -n true
if [[ "$(rustc --version | awk '{print $2}')" != 1.96.0 ]]; then
    echo "Rust 1.96.0 is required for candidate qualification" >&2
    exit 1
fi
if ! ldconfig -p | grep 'libpcap\.so' >/dev/null; then
    echo "the system libpcap runtime is unavailable" >&2
    exit 1
fi

temporary=""
input_kind="workspace"
archive_sha256=""
if [[ -n "${archive}" ]]; then
    input_kind="archive"
    archive="$(realpath "${archive}")"
    if [[ -n "${checksums}" ]]; then
        checksums="$(realpath "${checksums}")"
        expected_line="$(grep -E "  $(basename "${archive}")$" "${checksums}" || true)"
        if [[ -z "${expected_line}" ]]; then
            echo "SHA256SUMS has no entry for $(basename "${archive}")" >&2
            exit 1
        fi
        expected_sha256="${expected_line%% *}"
        actual_sha256="$(sha256sum "${archive}" | awk '{print $1}')"
        if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
            echo "candidate archive checksum mismatch" >&2
            exit 1
        fi
    fi
    archive_sha256="$(sha256sum "${archive}" | awk '{print $1}')"
    temporary="$(mktemp -d /tmp/packetcraftr-linux-live.XXXXXX)"
    tar -xzf "${archive}" -C "${temporary}"
    mapfile -t extracted < <(find "${temporary}" -mindepth 1 -maxdepth 1 -type d -print)
    if [[ "${#extracted[@]}" != 1 ]]; then
        echo "candidate archive must contain exactly one workspace root" >&2
        exit 1
    fi
    workspace="${extracted[0]}"
    readarray -t identity < <(
        python3 - "${workspace}" <<'PY'
import sys, tomllib
from pathlib import Path
root = Path(sys.argv[1])
release = tomllib.loads((root / "RELEASE-METADATA.toml").read_text())
cargo = tomllib.loads((root / "Cargo.toml").read_text())
print(release["commit"])
print(cargo["workspace"]["package"]["version"])
PY
    )
    candidate_commit="${identity[0]}"
    version="${identity[1]}"
else
    workspace="$(cd "${workspace}" && pwd)"
    working_tree_dirty=0
    if [[ -n "$(git -C "${workspace}" status --short)" ]]; then
        working_tree_dirty=1
    fi
    if [[ "${working_tree_dirty}" == 1 && "${allow_dirty}" != 1 ]]; then
        echo "workspace qualification requires a clean candidate tree" >&2
        exit 1
    fi
    candidate_commit="$(git -C "${workspace}" rev-parse HEAD)"
    version="$({
        git -C "${workspace}" show HEAD:Cargo.toml
    } | python3 -c 'import sys,tomllib; print(tomllib.loads(sys.stdin.read())["workspace"]["package"]["version"])')"
    archive_sha256="$(git -C "${workspace}" archive --format=tar HEAD | sha256sum | awk '{print $1}')"
fi
working_tree_dirty="${working_tree_dirty:-0}"
if [[ ! "${candidate_commit}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "candidate commit is not a full Git SHA: ${candidate_commit}" >&2
    exit 1
fi
if [[ -n "${expected_commit}" && "${candidate_commit}" != "${expected_commit}" ]]; then
    echo "candidate commit ${candidate_commit} differs from ${expected_commit}" >&2
    exit 1
fi

if [[ -e "${evidence}" ]] && [[ -n "$(find "${evidence}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "evidence directory must be absent or empty: ${evidence}" >&2
    exit 1
fi
mkdir -p "${evidence}"
evidence="$(cd "${evidence}" && pwd)"
if [[ -z "${bundle}" ]]; then
    bundle="${evidence}.tar.gz"
else
    bundle="$(realpath -m "${bundle}")"
fi

suffix="$((BASHPID % 10000))"
client_namespace="pcr-q49-client-${suffix}"
router_namespace="pcr-q49-router-${suffix}"
server_namespace="pcr-q49-server-${suffix}"
client_interface="c${suffix}"
router_client_interface="a${suffix}"
router_server_interface="b${suffix}"
server_interface="s${suffix}"
qualified_binary="/tmp/packetcraftr-q49-${suffix}"

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    for pid in $(jobs -pr); do
        kill "${pid}" >/dev/null 2>&1 || true
    done
    sudo -n ip netns delete "${client_namespace}" >/dev/null 2>&1 || true
    sudo -n ip netns delete "${router_namespace}" >/dev/null 2>&1 || true
    sudo -n ip netns delete "${server_namespace}" >/dev/null 2>&1 || true
    rm -f "${qualified_binary}"
    if [[ -n "${temporary}" ]]; then
        rm -rf "${temporary}"
    fi
    exit "${status}"
}
trap cleanup EXIT INT TERM

echo "[linux live] build exact candidate"
(
    cd "${workspace}"
    cargo build --locked --release --all-features
) 2>&1 | sed "s|${workspace}|<candidate-workspace>|g" | tee "${evidence}/build.log"
install -m 0755 "${workspace}/target/release/packetcraftr" "${qualified_binary}"
binary_sha256="$(sha256sum "${qualified_binary}" | awk '{print $1}')"
binary_version="$(${qualified_binary} --version)"
if [[ "${binary_version}" != "packetcraftr ${version}" ]]; then
    echo "candidate binary version mismatch: ${binary_version}" >&2
    exit 1
fi

echo "[linux live] run injected failure-path regressions"
(
    cd "${workspace}"
    cargo test --locked --workspace --all-features
) 2>&1 | sed "s|${workspace}|<candidate-workspace>|g" | tee "${evidence}/failure-path-tests.log"

echo "[linux live] provision disposable routed and Q-in-Q topology"
sudo -n ip netns add "${client_namespace}"
sudo -n ip netns add "${router_namespace}"
sudo -n ip netns add "${server_namespace}"
sudo -n ip link add "${client_interface}" type veth peer name "${router_client_interface}"
sudo -n ip link set "${client_interface}" netns "${client_namespace}"
sudo -n ip link set "${router_client_interface}" netns "${router_namespace}"
sudo -n ip link add "${router_server_interface}" type veth peer name "${server_interface}"
sudo -n ip link set "${router_server_interface}" netns "${router_namespace}"
sudo -n ip link set "${server_interface}" netns "${server_namespace}"
for namespace in "${client_namespace}" "${router_namespace}" "${server_namespace}"; do
    sudo -n ip -n "${namespace}" link set lo up
done
sudo -n ip -n "${client_namespace}" link set "${client_interface}" address 02:49:00:00:01:02 mtu 1280 up
sudo -n ip -n "${router_namespace}" link set "${router_client_interface}" address 02:49:00:00:01:01 mtu 1280 up
sudo -n ip -n "${router_namespace}" link set "${router_server_interface}" address 02:49:00:00:02:01 mtu 1280 up
sudo -n ip -n "${server_namespace}" link set "${server_interface}" address 02:49:00:00:02:02 mtu 1280 up
for spec in \
    "${client_namespace} ${client_interface}" \
    "${router_namespace} ${router_client_interface}" \
    "${router_namespace} ${router_server_interface}" \
    "${server_namespace} ${server_interface}"; do
    read -r namespace interface <<<"${spec}"
    sudo -n ip netns exec "${namespace}" ethtool -K "${interface}" \
        tx off tso off gso off gro off rxvlan off txvlan off \
        rx-vlan-stag-hw-parse off tx-vlan-stag-hw-insert off >/dev/null
done

sudo -n ip -n "${client_namespace}" address add 10.49.1.2/24 dev "${client_interface}"
sudo -n ip -n "${router_namespace}" address add 10.49.1.1/24 dev "${router_client_interface}"
sudo -n ip -n "${router_namespace}" address add 10.49.1.9/24 dev "${router_client_interface}"
sudo -n ip -n "${router_namespace}" address add 10.49.2.1/24 dev "${router_server_interface}"
sudo -n ip -n "${server_namespace}" address add 10.49.2.2/24 dev "${server_interface}"
sudo -n ip -n "${client_namespace}" -6 address add fd49:1::2/64 dev "${client_interface}" nodad
sudo -n ip -n "${router_namespace}" -6 address add fd49:1::1/64 dev "${router_client_interface}" nodad
sudo -n ip -n "${router_namespace}" -6 address add fd49:1::9/64 dev "${router_client_interface}" nodad
sudo -n ip -n "${router_namespace}" -6 address add fd49:2::1/64 dev "${router_server_interface}" nodad
sudo -n ip -n "${server_namespace}" -6 address add fd49:2::2/64 dev "${server_interface}" nodad
sudo -n ip -n "${client_namespace}" route add 10.49.2.0/24 via 10.49.1.1
sudo -n ip -n "${server_namespace}" route add 10.49.1.0/24 via 10.49.2.1
sudo -n ip -n "${client_namespace}" -6 route add fd49:2::/64 via fd49:1::1
sudo -n ip -n "${server_namespace}" -6 route add fd49:1::/64 via fd49:2::1
sudo -n ip netns exec "${router_namespace}" sysctl -qw net.ipv4.ip_forward=1
sudo -n ip netns exec "${router_namespace}" sysctl -qw net.ipv6.conf.all.forwarding=1

client_outer="${client_interface}.100"
router_outer="${router_client_interface}.100"
client_inner="${client_interface}.100.200"
router_inner="${router_client_interface}.100.200"
sudo -n ip -n "${client_namespace}" link add link "${client_interface}" name "${client_outer}" type vlan protocol 802.1ad id 100
sudo -n ip -n "${router_namespace}" link add link "${router_client_interface}" name "${router_outer}" type vlan protocol 802.1ad id 100
sudo -n ip -n "${client_namespace}" link set "${client_outer}" up
sudo -n ip -n "${router_namespace}" link set "${router_outer}" up
sudo -n ip -n "${client_namespace}" link add link "${client_outer}" name "${client_inner}" type vlan protocol 802.1Q id 200
sudo -n ip -n "${router_namespace}" link add link "${router_outer}" name "${router_inner}" type vlan protocol 802.1Q id 200
sudo -n ip -n "${client_namespace}" link set "${client_inner}" up
sudo -n ip -n "${router_namespace}" link set "${router_inner}" up
sudo -n ip -n "${client_namespace}" address add 10.49.100.2/24 dev "${client_inner}"
sudo -n ip -n "${router_namespace}" address add 10.49.100.1/24 dev "${router_inner}"

for _ in $(seq 1 20); do
    if sudo -n ip netns exec "${client_namespace}" ping -c 1 -W 1 10.49.2.2 >/dev/null 2>&1 &&
        sudo -n ip netns exec "${client_namespace}" ping -6 -c 1 -W 1 fd49:2::2 >/dev/null 2>&1 &&
        sudo -n ip netns exec "${client_namespace}" ping -c 1 -W 1 10.49.100.1 >/dev/null 2>&1; then
        topology_ready=1
        break
    fi
    sleep 0.1
done
if [[ "${topology_ready:-0}" != 1 ]]; then
    echo "qualification topology did not become ready" >&2
    exit 1
fi

python3 - "${evidence}/metadata.json" <<PY
import json, sys
metadata = {
    "schema": "packetcraftr.qualification-input/v1",
    "input_kind": "${input_kind}",
    "working_tree_dirty": bool(${working_tree_dirty}),
    "version": "${version}",
    "candidate_commit": "${candidate_commit}",
    "tooling_commit": "${tooling_commit}",
    "archive_sha256": "${archive_sha256}",
    "binary_sha256": "${binary_sha256}",
    "rust_version": "1.96.0",
    "topology": {
        "client_namespace": "${client_namespace}",
        "router_namespace": "${router_namespace}",
        "server_namespace": "${server_namespace}",
        "client_interface": "${client_interface}",
        "router_client_interface": "${router_client_interface}",
        "router_server_interface": "${router_server_interface}",
        "server_interface": "${server_interface}",
        "client_mac": "02:49:00:00:01:02",
        "gateway_mac": "02:49:00:00:01:01",
        "server_mac": "02:49:00:00:02:02",
        "ipv4": ["10.49.1.0/24", "10.49.2.0/24", "10.49.100.0/24"],
        "ipv6": ["fd49:1::/64", "fd49:2::/64"],
        "mtu": 1280,
        "outer_vlan": 100,
        "inner_vlan": 200,
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(metadata, output, indent=2)
    output.write("\n")
PY

{
    echo "kernel=$(uname -r)"
    echo "architecture=$(uname -m)"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "ip=$(ip -Version 2>&1)"
    echo "tcpdump=$(tcpdump --version 2>&1 | head -n 1)"
    dpkg-query -W -f='${Package}=${Version}\n' libpcap-dev iproute2 ethtool tcpdump 2>/dev/null || true
} >"${evidence}/runner-versions.txt"
for namespace in "${client_namespace}" "${router_namespace}" "${server_namespace}"; do
    echo "[${namespace}]"
    sudo -n ip -n "${namespace}" -brief address
    sudo -n ip -n "${namespace}" route
    sudo -n ip -n "${namespace}" -6 route
done >"${evidence}/topology.txt"

sudo -n ip netns exec "${server_namespace}" "${script_directory}/linux-live-peer.py" serve \
    --ipv4 10.49.2.2 --ipv6 fd49:2::2 >"${evidence}/peer.log" 2>&1 &
for _ in $(seq 1 50); do
    if sudo -n ip netns exec "${server_namespace}" ss -lunt | grep ':5353' >/dev/null; then
        peer_ready=1
        break
    fi
    sleep 0.1
done
if [[ "${peer_ready:-0}" != 1 ]]; then
    echo "qualification peer did not become ready" >&2
    exit 1
fi

client() {
    sudo -n ip netns exec "${client_namespace}" "${qualified_binary}" "$@"
}

run_json() {
    local output=$1
    shift
    client --output json "$@" >"${evidence}/${output}"
}

live_limits=(
    --max-queue-frames 64
    --max-captured-bytes 65536
    --snap-length 1500
)

echo "[linux live] passive discovery and route decisions"
run_json interfaces.json interfaces
run_json routes.json routes
run_json plan-onlink-ipv4.json plan \
    --packet 'ipv4(dst=10.49.1.9,identification=1)/udp(sport=40000,dport=9)' \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500
run_json plan-routed-ipv4.json plan \
    --packet 'ipv4(dst=10.49.2.2,identification=2)/udp(sport=40001,dport=9)' \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500
run_json plan-routed-ipv6.json plan \
    --packet 'ipv6(dst=fd49:2::2)/udp(sport=40002,dport=9)' \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500

echo "[linux live] active gateway ARP/NDP and Layer 2/Layer 3 sends"
sudo -n ip -n "${client_namespace}" neigh flush dev "${client_interface}" >/dev/null
run_json send-layer2-ipv4.json send \
    --packet 'ipv4(dst=10.49.2.2,identification=3)/udp(sport=40100,dport=9)/raw(text=layer2-ipv4)' \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500
sudo -n ip -n "${client_namespace}" -6 neigh flush dev "${client_interface}" >/dev/null
run_json send-layer2-ipv6.json send \
    --packet 'ipv6(dst=fd49:2::2)/udp(sport=40101,dport=9)/raw(text=layer2-ipv6)' \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500
run_json send-layer3-ipv4.json send \
    --packet 'ipv4(dst=10.49.2.2,identification=4)/udp(sport=40102,dport=9)/raw(text=layer3-ipv4)' \
    --interface "${client_interface}" --link-mode layer3 --max-packets 1 --max-bytes 1500

echo "[linux live] capture-ready exchanges"
run_json exchange-ipv4.json exchange \
    --packet 'ipv4(dst=10.49.2.2,identification=5)/udp(sport=41000,dport=9000)/raw(text=exchange-ipv4)' \
    --interface "${client_interface}" --link-mode layer2 --timeout-ms 1000 \
    --max-packets 1 --max-bytes 1500 --max-responses 1 --max-unsolicited 8 \
    "${live_limits[@]}"
run_json exchange-ipv6.json exchange \
    --packet 'ipv6(dst=fd49:2::2)/udp(sport=41001,dport=9000)/raw(text=exchange-ipv6)' \
    --interface "${client_interface}" --link-mode layer3 --timeout-ms 1000 \
    --max-packets 1 --max-bytes 1500 --max-responses 1 --max-unsolicited 8 \
    "${live_limits[@]}"

echo "[linux live] finite capture and capture-file readback"
client --output pcapng capture \
    --packet 'ipv4(dst=10.49.2.2,identification=6)/udp(dport=9)' \
    --interface "${client_interface}" --timeout-ms 600 --max-packets 8 --max-bytes 12000 \
    "${live_limits[@]}" >"${evidence}/capture.pcapng" 2>"${evidence}/capture.stderr" &
capture_pid=$!
sleep 0.2
sudo -n ip netns exec "${server_namespace}" ping -c 1 -W 1 10.49.1.2 >/dev/null
wait "${capture_pid}"
"${qualified_binary}" --output ndjson read "${evidence}/capture.pcapng" \
    --max-frames 8 --max-bytes 12000 --max-frame-bytes 1500 --max-interfaces 8 \
    >"${evidence}/capture-read.ndjson"

echo "[linux live] byte-identical stacked VLAN replay"
# Creating VLAN devices can update the parent feature state on some kernels;
# restate the exact-byte capture boundary immediately before this probe.
sudo -n ip netns exec "${client_namespace}" ethtool -K "${client_interface}" \
    rxvlan off txvlan off rx-vlan-stag-hw-parse off tx-vlan-stag-hw-insert off >/dev/null
sudo -n ip netns exec "${router_namespace}" ethtool -K "${router_client_interface}" \
    rxvlan off txvlan off rx-vlan-stag-hw-parse off tx-vlan-stag-hw-insert off >/dev/null
stacked_packet='eth(src=02:49:00:00:01:02,dst=02:49:00:00:01:01)/qinq(vid=100)/vlan(vid=200)/ipv4(src=10.49.100.2,dst=10.49.100.1,identification=49)/udp(sport=44000,dport=9000)/raw(text=stacked-vlan)'
stacked_hex="$(${qualified_binary} --output hex build --packet "${stacked_packet}")"
printf '%s\n' "${stacked_hex}" >"${evidence}/stacked-vlan.hex"
"${script_directory}/linux-live-peer.py" make-pcap --frame-hex "${stacked_hex}" \
    --output "${evidence}/stacked-vlan-source.pcap"
touch "${evidence}/stacked-vlan-captured.pcap"
chmod 0666 "${evidence}/stacked-vlan-captured.pcap"
sudo -n ip netns exec "${router_namespace}" timeout 3 tcpdump -U \
    -i "${router_client_interface}" -c 1 -w "${evidence}/stacked-vlan-captured.pcap" \
    'ether proto 0x88a8' \
    >"${evidence}/stacked-vlan-tcpdump.log" 2>&1 &
tcpdump_pid=$!
sleep 0.3
run_json stacked-vlan-replay.json replay "${evidence}/stacked-vlan-source.pcap" \
    --interface "${client_interface}" --link-mode layer2 --timing immediate \
    --max-packets 1 --max-bytes 1500 --max-frame-bytes 1500 \
    --allow-malformed-live --allow-permissive-packets
wait "${tcpdump_pid}"
"${qualified_binary}" --output ndjson read "${evidence}/stacked-vlan-source.pcap" \
    >"${evidence}/stacked-vlan-source.ndjson"
"${qualified_binary}" --output ndjson read "${evidence}/stacked-vlan-captured.pcap" \
    >"${evidence}/stacked-vlan-captured.ndjson"

echo "[linux live] bounded scan and traceroute"
run_json scan-ipv4.json scan 10.49.2.2 --transport tcp --ports 9443 --attempts 1 \
    --timeout-ms 500 --batch-size 1 --rate 10 --max-probes 1 --max-duration-ms 2000 \
    --interface "${client_interface}" --link-mode layer3 --max-packets 1 --max-bytes 1500 \
    "${live_limits[@]}"
run_json scan-ipv6.json scan fd49:2::2 --transport icmp --family ipv6 --attempts 1 \
    --timeout-ms 500 --batch-size 1 --rate 10 --max-probes 1 --max-duration-ms 2000 \
    --interface "${client_interface}" --link-mode layer3 --max-packets 1 --max-bytes 1500 \
    "${live_limits[@]}"
run_json traceroute-ipv4.json traceroute 10.49.2.2 --strategy udp --first-hop 1 \
    --max-hops 2 --attempts 1 --timeout-ms 500 --rate 10 --max-probes 2 \
    --max-duration-ms 3000 --interface "${client_interface}" --link-mode layer3 \
    --max-packets 2 --max-bytes 3000 "${live_limits[@]}"
run_json traceroute-ipv6.json traceroute fd49:2::2 --strategy udp --family ipv6 \
    --first-hop 1 --max-hops 2 --attempts 1 --timeout-ms 500 --rate 10 --max-probes 2 \
    --max-duration-ms 3000 --interface "${client_interface}" --link-mode layer3 \
    --max-packets 2 --max-bytes 3000 "${live_limits[@]}"

echo "[linux live] bounded structured DNS"
run_json dns-ipv4.json dns 10.49.2.2 www.example.test --type a --port 5353 \
    --transaction-id 18761 --source-port 42000 --attempts 1 --timeout-ms 500 --rate 10 \
    --max-duration-ms 2000 --interface "${client_interface}" --link-mode layer3 \
    --max-packets 1 --max-bytes 1500 "${live_limits[@]}"
run_json dns-ipv6.json dns fd49:2::2 www.example.test --type a --port 5353 \
    --transaction-id 18762 --source-port 42001 --attempts 1 --timeout-ms 500 --rate 10 \
    --max-duration-ms 2000 --interface "${client_interface}" --link-mode layer3 \
    --max-packets 1 --max-bytes 1500 "${live_limits[@]}"

echo "[linux live] every bounded live-fuzz strategy"
fuzz_packet='ipv4(dst=10.49.2.2,identification=50)/udp(sport=43000,dport=9000)/raw(text=hello)'
for strategy in boundary random bit-flip; do
    run_json "fuzz-${strategy}.json" fuzz --packet "${fuzz_packet}" --seed 49 --cases 1 \
        --strategy "${strategy}" --field 2.bytes --live --timeout-ms 500 --rate 10 \
        --max-cases 1 --max-total-bytes 65536 --max-field-bytes 64 --max-list-items 8 \
        --max-shrink-steps 2 --max-duration-ms 2000 --interface "${client_interface}" \
        --link-mode layer3 --max-packets 1 --max-bytes 1500 "${live_limits[@]}"
done
run_json fuzz-malformed.json fuzz --packet "${fuzz_packet}" --seed 49 --cases 1 \
    --strategy malformed --field 0.checksum --mode permissive --live \
    --allow-malformed-live --allow-permissive-packets --timeout-ms 200 --rate 10 \
    --max-cases 1 --max-total-bytes 65536 --max-field-bytes 64 --max-list-items 8 \
    --max-shrink-steps 2 --max-duration-ms 1000 --interface "${client_interface}" \
    --link-mode layer2 --max-packets 1 --max-bytes 1500 "${live_limits[@]}"

echo "[linux live] timeout, malformed/unrelated evidence, privilege, and MTU failures"
client --output json exchange \
    --packet 'ipv4(dst=10.49.2.99,identification=51)/udp(sport=45000,dport=9001)/raw(text=timeout)' \
    --interface "${client_interface}" --link-mode layer3 --timeout-ms 350 \
    --max-packets 1 --max-bytes 1500 --max-responses 1 --max-unsolicited 8 \
    "${live_limits[@]}" >"${evidence}/timeout-malformed.json" &
timeout_pid=$!
sleep 0.12
sudo -n ip netns exec "${router_namespace}" "${script_directory}/linux-live-peer.py" inject \
    --interface "${router_client_interface}" \
    --frame-hex 0249000001020249000001010800450000100000
wait "${timeout_pid}"

set +e
sudo -n ip netns exec "${client_namespace}" setpriv \
    --reuid=65534 --regid=65534 --clear-groups "${qualified_binary}" \
    --output ndjson capture \
    --packet 'ipv4(dst=10.49.2.2,identification=52)/udp(dport=9)' \
    --interface "${client_interface}" --timeout-ms 100 --max-packets 1 --max-bytes 1500 \
    --max-queue-frames 8 --max-captured-bytes 12000 --snap-length 1500 \
    >"${evidence}/unprivileged-capture.ndjson"
unprivileged_status=$?
set -e
printf '%s\n' "${unprivileged_status}" >"${evidence}/unprivileged-capture.exit"

payload="$(python3 -c 'print("x" * 1300)')"
set +e
client --output json send \
    --packet "ipv4(dst=10.49.2.2,identification=53)/udp(sport=45001,dport=9000)/raw(text=\"${payload}\")" \
    --interface "${client_interface}" --link-mode layer3 --max-packets 1 --max-bytes 2000 \
    >"${evidence}/low-mtu.json"
mtu_status=$?
set -e
printf '%s\n' "${mtu_status}" >"${evidence}/low-mtu.exit"

echo "[linux live] validate, checksum, and bundle evidence"
"${script_directory}/verify-linux-live-evidence.py" --evidence "${evidence}"
(
    cd "${evidence}"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
    sha256sum --check SHA256SUMS
)
tar --sort=name -czf "${bundle}" -C "$(dirname "${evidence}")" "$(basename "${evidence}")"
bundle_sha256="$(sha256sum "${bundle}" | awk '{print $1}')"
echo "Linux live qualification passed"
echo "evidence=${evidence}"
echo "bundle=${bundle}"
echo "bundle_sha256=${bundle_sha256}"
