#!/usr/bin/env bash
set -euo pipefail

# Copyright (C) 2026 tyk-swe
# SPDX-License-Identifier: AGPL-3.0-only

usage() {
    cat >&2 <<'EOF'
usage: scripts/qualify-macos-live.sh \
  (--archive PATH [--checksums PATH] | --workspace PATH) \
  --expected-architecture arm64|x86_64 --evidence DIRECTORY \
  [--bundle PATH] [--expected-commit SHA]

Runs real native route, BPF capture/injection, neighbor, raw-socket, and tool
traffic over a disposable paired feth link. An archive is required for release
sign-off; workspace mode exists only for harness development.
EOF
}

archive=""
checksums=""
workspace=""
expected_architecture=""
expected_commit=""
evidence=""
bundle=""
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --archive) archive="${2:-}"; shift 2 ;;
        --checksums) checksums="${2:-}"; shift 2 ;;
        --workspace) workspace="${2:-}"; shift 2 ;;
        --expected-architecture) expected_architecture="${2:-}"; shift 2 ;;
        --expected-commit) expected_commit="${2:-}"; shift 2 ;;
        --evidence) evidence="${2:-}"; shift 2 ;;
        --bundle) bundle="${2:-}"; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done
if [[ -z "${evidence}" || -z "${expected_architecture}" ]] ||
    [[ -n "${archive}" && -n "${workspace}" ]] ||
    [[ -z "${archive}" && -z "${workspace}" ]]; then
    usage
    exit 2
fi
if [[ "${expected_architecture}" != arm64 && "${expected_architecture}" != x86_64 ]]; then
    echo "expected architecture must be arm64 or x86_64" >&2
    exit 2
fi

root="$(git rev-parse --show-toplevel)"
tooling_commit="$(git -C "${root}" rev-parse HEAD)"
for command in arp cargo find grep ifconfig install python3 route rustc sed shasum sudo tar tcpdump; do
    if ! command -v "${command}" >/dev/null 2>&1; then
        echo "required macOS qualification command is unavailable: ${command}" >&2
        exit 1
    fi
done
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != "${expected_architecture}" ]]; then
    echo "runner architecture differs: expected ${expected_architecture}, got $(uname -s)/$(uname -m)" >&2
    exit 1
fi
sudo -n true
if [[ "$(rustc --version | awk '{print $2}')" != 1.96.0 ]]; then
    echo "Rust 1.96.0 is required for candidate qualification" >&2
    exit 1
fi

temporary="$(mktemp -d /tmp/packetcraftr-macos-live.XXXXXX)"
input_kind="workspace"
archive_sha256=""
if [[ -n "${archive}" ]]; then
    input_kind="archive"
    archive="$(cd "$(dirname "${archive}")" && pwd)/$(basename "${archive}")"
    archive_sha256="$(shasum -a 256 "${archive}" | awk '{print $1}')"
    if [[ -n "${checksums}" ]]; then
        checksums="$(cd "$(dirname "${checksums}")" && pwd)/$(basename "${checksums}")"
        expected_line="$(grep -E "  $(basename "${archive}")$" "${checksums}" || true)"
        if [[ -z "${expected_line}" || "${expected_line%% *}" != "${archive_sha256}" ]]; then
            echo "candidate archive checksum mismatch" >&2
            exit 1
        fi
    fi
    tar -xzf "${archive}" -C "${temporary}"
    workspace="$(find "${temporary}" -mindepth 1 -maxdepth 1 -type d -print)"
    if [[ -z "${workspace}" || "$(printf '%s\n' "${workspace}" | wc -l | tr -d ' ')" != 1 ]]; then
        echo "candidate archive must contain exactly one workspace root" >&2
        exit 1
    fi
    identity="$(python3 - "${workspace}" <<'PY'
import sys, tomllib
from pathlib import Path
root = Path(sys.argv[1])
release = tomllib.loads((root / "RELEASE-METADATA.toml").read_text())
cargo = tomllib.loads((root / "Cargo.toml").read_text())
print(release["commit"], cargo["workspace"]["package"]["version"])
PY
)"
    candidate_commit="${identity%% *}"
    version="${identity#* }"
else
    workspace="$(cd "${workspace}" && pwd)"
    if [[ -n "$(git -C "${workspace}" status --short)" ]]; then
        echo "workspace qualification requires a clean candidate tree" >&2
        exit 1
    fi
    candidate_commit="$(git -C "${workspace}" rev-parse HEAD)"
    version="$(git -C "${workspace}" show HEAD:Cargo.toml | python3 -c \
        'import sys,tomllib; print(tomllib.loads(sys.stdin.read())["workspace"]["package"]["version"])')"
    archive_sha256="$(git -C "${workspace}" archive --format=tar HEAD | shasum -a 256 | awk '{print $1}')"
fi
if [[ ! "${candidate_commit}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "candidate commit is not a full Git SHA" >&2
    exit 1
fi
if [[ -n "${expected_commit}" && "${candidate_commit}" != "${expected_commit}" ]]; then
    echo "candidate commit ${candidate_commit} differs from ${expected_commit}" >&2
    exit 1
fi

if [[ -e "${evidence}" && -n "$(find "${evidence}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "evidence directory must be absent or empty: ${evidence}" >&2
    exit 1
fi
mkdir -p "${evidence}"
evidence="$(cd "${evidence}" && pwd)"
if [[ -z "${bundle}" ]]; then
    bundle="${evidence}.tar.gz"
else
    mkdir -p "$(dirname "${bundle}")"
    bundle="$(cd "$(dirname "${bundle}")" && pwd)/$(basename "${bundle}")"
fi

unit=$((($$ % 100) + 200))
while ifconfig "feth${unit}" >/dev/null 2>&1 || ifconfig "feth$((unit + 1))" >/dev/null 2>&1; do
    unit=$((unit + 2))
done
client_interface="feth${unit}"
peer_interface="feth$((unit + 1))"
qualified_binary="/tmp/packetcraftr-q50-${expected_architecture}-$$"
peer_binary="/tmp/packetcraftr-q50-peer-${expected_architecture}-$$"
peer_ready_file="${evidence}/peer.ready"
peer_stop_file="${evidence}/peer.stop"
peer_report_file="${evidence}/peer-report.json"
peer_pid=""
client_ipv4="10.50.1.2"
peer_ipv4="10.50.1.9"
client_ipv6="fd50:1::2"
peer_ipv6="fd50:1::9"
client_mac="02:50:00:00:01:02"
peer_mac="02:50:00:00:01:09"

cleanup() {
    status=$?
    trap - EXIT INT TERM
    touch "${peer_stop_file}" >/dev/null 2>&1 || true
    for pid in $(jobs -pr); do
        kill "${pid}" >/dev/null 2>&1 || true
    done
    sudo -n ifconfig "${client_interface}" destroy >/dev/null 2>&1 || true
    sudo -n ifconfig "${peer_interface}" destroy >/dev/null 2>&1 || true
    rm -f "${qualified_binary}" "${peer_binary}"
    rm -rf "${temporary}"
    exit "${status}"
}
trap cleanup EXIT INT TERM

echo "[macOS live] build and test exact candidate"
(
    cd "${workspace}"
    cargo build --locked --release --all-features \
        --bin packetcraftr --example live_qualification_peer
) >"${evidence}/build.log" 2>&1
install -m 0755 "${workspace}/target/release/packetcraftr" "${qualified_binary}"
install -m 0755 "${workspace}/target/release/examples/live_qualification_peer" "${peer_binary}"
binary_sha256="$(shasum -a 256 "${qualified_binary}" | awk '{print $1}')"
peer_binary_sha256="$(shasum -a 256 "${peer_binary}" | awk '{print $1}')"
if [[ "$("${qualified_binary}" --version)" != "packetcraftr ${version}" ]]; then
    echo "candidate binary version mismatch" >&2
    exit 1
fi
(
    cd "${workspace}"
    cargo test --locked --workspace --all-features
    cargo test --locked --all-features --example live_qualification_peer
) >"${evidence}/failure-path-tests.log" 2>&1

echo "[macOS live] create isolated paired feth/BPF topology"
sudo -n ifconfig "${client_interface}" create
sudo -n ifconfig "${peer_interface}" create
sudo -n ifconfig "${client_interface}" peer "${peer_interface}"
sudo -n ifconfig "${client_interface}" ether "${client_mac}"
sudo -n ifconfig "${peer_interface}" ether "${peer_mac}"
sudo -n ifconfig "${client_interface}" mtu 1280
sudo -n ifconfig "${peer_interface}" mtu 1280
sudo -n ifconfig "${client_interface}" inet "${client_ipv4}" netmask 255.255.255.0 up
sudo -n ifconfig "${client_interface}" inet6 "${client_ipv6}" prefixlen 64 alias
sudo -n ifconfig "${peer_interface}" up

rm -f "${peer_ready_file}" "${peer_stop_file}" "${peer_report_file}"
sudo -n "${peer_binary}" \
    --interface "${peer_interface}" \
    --client-mac "${client_mac}" --peer-mac "${peer_mac}" \
    --client-ipv4 "${client_ipv4}" --peer-ipv4 "${peer_ipv4}" \
    --client-ipv6 "${client_ipv6}" --peer-ipv6 "${peer_ipv6}" \
    --ready-file "${peer_ready_file}" --stop-file "${peer_stop_file}" \
    --report-file "${peer_report_file}" >"${evidence}/peer.log" 2>&1 &
peer_pid=$!
peer_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [[ -f "${peer_ready_file}" ]]; then
        peer_ready=1
        break
    fi
    if ! kill -0 "${peer_pid}" >/dev/null 2>&1; then
        cat "${evidence}/peer.log" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "${peer_ready}" != 1 ]]; then
    echo "qualification peer did not become ready" >&2
    exit 1
fi

ipv6_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    client_ipv6_state="$(ifconfig "${client_interface}" | grep "inet6 ${client_ipv6} " || true)"
    if [[ -n "${client_ipv6_state}" && "${client_ipv6_state}" != *tentative* &&
        "${client_ipv6_state}" != *duplicated* ]]; then
        ipv6_ready=1
        break
    fi
    sleep 0.25
done
if [[ "${ipv6_ready}" != 1 ]]; then
    echo "client IPv6 address did not complete duplicate-address detection" >&2
    ifconfig "${client_interface}" >&2 || true
    exit 1
fi

python3 - "${evidence}/metadata.json" <<PY
import json, os, sys
metadata = {
    "schema": "packetcraftr.qualification-input/v1",
    "platform": "macos",
    "architecture": "${expected_architecture}",
    "input_kind": "${input_kind}",
    "version": "${version}",
    "candidate_commit": "${candidate_commit}",
    "tooling_commit": "${tooling_commit}",
    "archive_sha256": "${archive_sha256}",
    "binary_sha256": "${binary_sha256}",
    "peer_binary_sha256": "${peer_binary_sha256}",
    "rust_version": "1.96.0",
    "runner_image": os.environ.get("ImageOS"),
    "runner_image_version": os.environ.get("ImageVersion"),
    "topology": {
        "kind": "paired-feth",
        "client_interface": "${client_interface}",
        "peer_interface": "${peer_interface}",
        "client_mac": "${client_mac}",
        "peer_mac": "${peer_mac}",
        "client_ipv4": "${client_ipv4}",
        "peer_ipv4": "${peer_ipv4}",
        "client_ipv6": "${client_ipv6}",
        "peer_ipv6": "${peer_ipv6}",
        "mtu": 1280,
        "peer_mode": "packetcraftr-native-bpf",
        "peer_interface_addresses": "none",
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(metadata, output, indent=2)
    output.write("\n")
PY
{
    echo "sw_vers=$(sw_vers -productVersion)"
    echo "kernel=$(uname -r)"
    echo "architecture=$(uname -m)"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "libpcap=$(tcpdump --version 2>&1 | head -n 1)"
    echo "runner_image=${ImageOS:-}"
    echo "runner_image_version=${ImageVersion:-}"
} >"${evidence}/runner-versions.txt"
{
    ifconfig "${client_interface}"
    ifconfig "${peer_interface}"
    route -n get -ifscope "${client_interface}" "${peer_ipv4}" || true
    route -n get -inet6 -ifscope "${client_interface}" "${peer_ipv6}" || true
} >"${evidence}/topology.txt" 2>&1

client() {
    sudo -n "${qualified_binary}" "$@"
}
run_json() {
    output=$1
    shift
    client --output json "$@" >"${evidence}/${output}"
}
live_limits=(--max-queue-frames 64 --max-captured-bytes 65536 --snap-length 1500)

echo "[macOS live] route, neighbor, Layer 2, and raw Layer 3"
run_json interfaces.json interfaces
run_json routes.json routes
run_json plan-ipv4.json plan \
    --packet "ipv4(dst=${peer_ipv4},identification=501)/udp(sport=40000,dport=9)" \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500
run_json plan-ipv6.json plan \
    --packet "ipv6(dst=${peer_ipv6})/udp(sport=40001,dport=9)" \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500
sudo -n arp -d "${peer_ipv4}" >/dev/null 2>&1 || true
run_json send-layer2-ipv4.json send \
    --packet "ipv4(dst=${peer_ipv4},identification=502)/udp(sport=40100,dport=9000)/raw(text=layer2-ipv4)" \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500
run_json send-layer2-ipv6.json send \
    --packet "ipv6(dst=${peer_ipv6})/udp(sport=40101,dport=9000)/raw(text=layer2-ipv6)" \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500
run_json send-layer3-ipv4.json send \
    --packet "ipv4(dst=${peer_ipv4},identification=503)/udp(sport=40102,dport=9000)/raw(text=layer3-ipv4)" \
    --interface "${client_interface}" --link-mode layer3 --max-packets 1 --max-bytes 1500
set +e
client --output json send \
    --packet "ipv6(dst=${peer_ipv6})/udp(sport=40103,dport=9000)/raw(text=layer3-ipv6)" \
    --interface "${client_interface}" --link-mode layer3 --max-packets 1 --max-bytes 1500 \
    >"${evidence}/send-layer3-ipv6.json"
layer3_ipv6_status=$?
set -e
printf '%s\n' "${layer3_ipv6_status}" >"${evidence}/send-layer3-ipv6.exit"

echo "[macOS live] capture-ready exchange and finite capture"
run_json exchange-ipv4.json exchange \
    --packet "ipv4(dst=${peer_ipv4},identification=504)/udp(sport=41000,dport=9000)/raw(text=exchange-ipv4)" \
    --interface "${client_interface}" --link-mode layer2 --timeout-ms 1200 \
    --max-packets 1 --max-bytes 1500 --max-responses 1 --max-unsolicited 8 "${live_limits[@]}"
run_json exchange-ipv6.json exchange \
    --packet "ipv6(dst=${peer_ipv6})/udp(sport=41001,dport=9000)/raw(text=exchange-ipv6)" \
    --interface "${client_interface}" --link-mode layer2 --timeout-ms 1200 \
    --max-packets 1 --max-bytes 1500 --max-responses 1 --max-unsolicited 8 "${live_limits[@]}"

client --output pcapng capture \
    --packet "eth(source=${peer_mac},destination=${client_mac},ether_type=2048)/raw(hex=00)" \
    --interface "${client_interface}" --timeout-ms 800 --max-packets 8 --max-bytes 12000 \
    "${live_limits[@]}" >"${evidence}/capture.pcapng" 2>"${evidence}/capture.stderr" &
capture_pid=$!
sleep 0.25
capture_trigger_hex="$("${qualified_binary}" --output hex build \
    --packet "ipv4(src=${peer_ipv4},dst=${client_ipv4},identification=505)/udp(sport=9000,dport=9)/raw(text=capture)")"
client --output json send \
    --packet "eth(source=${peer_mac},destination=${client_mac},ether_type=2048)/raw(hex=${capture_trigger_hex})" \
    --interface "${peer_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500 \
    >"${evidence}/capture-trigger.json"
wait "${capture_pid}"
"${qualified_binary}" --output ndjson read "${evidence}/capture.pcapng" \
    --max-frames 8 --max-bytes 12000 --max-frame-bytes 1500 --max-interfaces 8 \
    >"${evidence}/capture-read.ndjson"

echo "[macOS live] exact stacked-VLAN replay over BPF"
stacked_packet="eth(src=${client_mac},dst=${peer_mac})/qinq(vid=100)/vlan(vid=200)/ipv4(src=${client_ipv4},dst=${peer_ipv4},identification=506)/udp(sport=44000,dport=9000)/raw(text=stacked-vlan)"
stacked_hex="$("${qualified_binary}" --output hex build --packet "${stacked_packet}")"
printf '%s\n' "${stacked_hex}" >"${evidence}/stacked-vlan.hex"
python3 "${root}/scripts/linux-live-peer.py" make-pcap --frame-hex "${stacked_hex}" \
    --output "${evidence}/stacked-vlan-source.pcap"
touch "${evidence}/stacked-vlan-captured.pcap"
chmod 0666 "${evidence}/stacked-vlan-captured.pcap"
sudo -n tcpdump -U -i "${peer_interface}" -c 1 -w "${evidence}/stacked-vlan-captured.pcap" \
    'ether proto 0x88a8' >"${evidence}/stacked-vlan-tcpdump.log" 2>&1 &
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

echo "[macOS live] scan, traceroute, DNS, and every bounded fuzz strategy"
run_json scan-ipv4.json scan "${peer_ipv4}" --transport tcp --ports 9443 --attempts 1 \
    --timeout-ms 700 --batch-size 1 --rate 10 --max-probes 1 --max-duration-ms 2500 \
    --interface "${client_interface}" --link-mode layer3 --max-packets 1 --max-bytes 1500 \
    "${live_limits[@]}"
run_json scan-ipv6.json scan "${peer_ipv6}" --transport icmp --family ipv6 --attempts 1 \
    --timeout-ms 700 --batch-size 1 --rate 10 --max-probes 1 --max-duration-ms 2500 \
    --interface "${client_interface}" --link-mode layer2 --max-packets 1 --max-bytes 1500 \
    "${live_limits[@]}"
run_json traceroute-ipv4.json traceroute "${peer_ipv4}" --strategy udp --first-hop 1 \
    --max-hops 1 --attempts 1 --timeout-ms 700 --rate 10 --max-probes 1 \
    --max-duration-ms 2500 --interface "${client_interface}" --link-mode layer3 \
    --max-packets 1 --max-bytes 1500 "${live_limits[@]}"
run_json traceroute-ipv6.json traceroute "${peer_ipv6}" --strategy udp --family ipv6 \
    --first-hop 1 --max-hops 1 --attempts 1 --timeout-ms 700 --rate 10 --max-probes 1 \
    --max-duration-ms 2500 --interface "${client_interface}" --link-mode layer2 \
    --max-packets 1 --max-bytes 1500 "${live_limits[@]}"
run_json dns-ipv4.json dns "${peer_ipv4}" www.example.test --type a --port 5353 \
    --transaction-id 20501 --source-port 42000 --attempts 1 --timeout-ms 700 --rate 10 \
    --max-duration-ms 2500 --interface "${client_interface}" --link-mode layer3 \
    --max-packets 1 --max-bytes 1500 "${live_limits[@]}"
run_json dns-ipv6.json dns "${peer_ipv6}" www.example.test --type a --port 5353 \
    --transaction-id 20502 --source-port 42001 --attempts 1 --timeout-ms 700 --rate 10 \
    --max-duration-ms 2500 --interface "${client_interface}" --link-mode layer2 \
    --max-packets 1 --max-bytes 1500 "${live_limits[@]}"

fuzz_packet="ipv4(dst=${peer_ipv4},identification=507)/udp(sport=43000,dport=9000)/raw(text=hello)"
for strategy in boundary random bit-flip; do
    run_json "fuzz-${strategy}.json" fuzz --packet "${fuzz_packet}" --seed 50 --cases 1 \
        --strategy "${strategy}" --field 2.bytes --live --timeout-ms 700 --rate 10 \
        --max-cases 1 --max-total-bytes 65536 --max-field-bytes 64 --max-list-items 8 \
        --max-shrink-steps 2 --max-duration-ms 2500 --interface "${client_interface}" \
        --link-mode layer3 --max-packets 1 --max-bytes 1500 "${live_limits[@]}"
done
run_json fuzz-malformed.json fuzz --packet "${fuzz_packet}" --seed 50 --cases 1 \
    --strategy malformed --field 0.checksum --mode permissive --live \
    --allow-malformed-live --allow-permissive-packets --timeout-ms 300 --rate 10 \
    --max-cases 1 --max-total-bytes 65536 --max-field-bytes 64 --max-list-items 8 \
    --max-shrink-steps 2 --max-duration-ms 1500 --interface "${client_interface}" \
    --link-mode layer2 --max-packets 1 --max-bytes 1500 "${live_limits[@]}"

echo "[macOS live] privilege and low-MTU failures"
set +e
sudo -n -u nobody "${qualified_binary}" --output ndjson capture \
    --packet "ipv4(dst=${peer_ipv4},identification=508)/udp(dport=9)" \
    --interface "${client_interface}" --timeout-ms 100 --max-packets 1 --max-bytes 1500 \
    --max-queue-frames 8 --max-captured-bytes 12000 --snap-length 1500 \
    >"${evidence}/unprivileged-capture.ndjson"
unprivileged_status=$?
set -e
printf '%s\n' "${unprivileged_status}" >"${evidence}/unprivileged-capture.exit"

payload="$(python3 -c 'print("x" * 1300)')"
set +e
client --output json send \
    --packet "ipv4(dst=${peer_ipv4},identification=509)/udp(sport=45001,dport=9000)/raw(text=\"${payload}\")" \
    --interface "${client_interface}" --link-mode layer3 --max-packets 1 --max-bytes 2000 \
    >"${evidence}/low-mtu.json"
mtu_status=$?
set -e
printf '%s\n' "${mtu_status}" >"${evidence}/low-mtu.exit"

echo "[macOS live] validate and bundle evidence"
touch "${peer_stop_file}"
wait "${peer_pid}"
peer_pid=""
python3 "${root}/scripts/verify-macos-live-evidence.py" --evidence "${evidence}"
python3 - "${evidence}" <<'PY'
import hashlib, sys
from pathlib import Path
root = Path(sys.argv[1])
rows = []
for path in sorted(root.iterdir()):
    if path.is_file() and path.name != "SHA256SUMS":
        rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
(root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
PY
(
    cd "${evidence}"
    shasum -a 256 -c SHA256SUMS
)
tar -czf "${bundle}" -C "$(dirname "${evidence}")" "$(basename "${evidence}")"
bundle_sha256="$(shasum -a 256 "${bundle}" | awk '{print $1}')"
echo "macOS ${expected_architecture} live qualification passed"
echo "evidence=${evidence}"
echo "bundle=${bundle}"
echo "bundle_sha256=${bundle_sha256}"
