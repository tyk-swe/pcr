# Privileged Linux live-I/O qualification

This is the release-signoff procedure for PacketcraftR's advertised Linux
native route, Layer 2, and raw Layer 3 paths. Ordinary hosted CI remains
unprivileged and cannot replace this gate.

## Runner boundary

Use a disposable, single-tenant Ubuntu 24.04 x86_64 runner carrying the fixed
GitHub labels `self-hosted`, `Linux`, `X64`, and `packetcraftr-live`. Protect the
`privileged-release-qualification` environment so only a reviewed candidate
and reviewed qualification-tooling ref can reach it. Never attach the label to
a shared development host or allow pull-request code to target it.

The approved image contains Rust 1.96.0, `libpcap-dev` 1.10.4, `iproute2` 6.1,
`ethtool`, `tcpdump` 4.99, Python 3, `setpriv`, GNU `tar`, and `sha256sum`.
Record the installed distribution revisions in the retained evidence; these
major/minor values describe the reproducible baseline rather than authorizing
an unreviewed downgrade.

The harness needs root for namespace/link/route creation, namespace-local
forwarding, offload control, native capture/injection, and raw sockets. In
particular, `ip netns exec` is effectively a broad root boundary and cannot be
honestly represented as only `CAP_NET_RAW`. The runner is therefore disposable
and passwordless `sudo` is permitted only inside its protected qualification
job. The harness uses three uniquely named namespaces, private/documentation
addresses, deterministic locally administered MAC addresses, and a `trap` that
deletes the namespaces on success, failure, or interruption. No host interface
or route is modified.

## Candidate invocation

Download both assets from the candidate's GitHub Release, then run:

```console
mkdir -p /tmp/packetcraftr-candidate
release_tag=v0.2.0-rc.1
source_commit="$(gh api "repos/tyk-swe/pcr/git/ref/tags/${release_tag}" --jq .object.sha)"
gh release download "${release_tag}" --repo tyk-swe/pcr \
  --pattern 'packetcraftr-workspace-*.tar.gz' --pattern SHA256SUMS \
  --dir /tmp/packetcraftr-candidate
(cd /tmp/packetcraftr-candidate && sha256sum --check SHA256SUMS)
scripts/qualify-linux-live.sh \
  --archive /tmp/packetcraftr-candidate/packetcraftr-workspace-0.2.0-rc.1.tar.gz \
  --checksums /tmp/packetcraftr-candidate/SHA256SUMS \
  --expected-commit "${source_commit}" \
  --evidence /tmp/packetcraftr-linux-live
```

`--workspace` exists for harness development, requires a clean tree by default,
and is not release-signoff evidence. `--allow-dirty` makes an explicitly marked
development run possible while changing the harness. The protected manual workflow always downloads and
authenticates the GitHub archive. If qualification finds a defect, preserve
the failing bundle, fix the defect on a later candidate, and rerun the whole
matrix. Never move the earlier tag or replace its assets.

## Topology and matrix

The client and server occupy different 1280-byte-MTU Ethernet segments joined
by a forwarding router. Both segments carry IPv4 and IPv6. A separate Q-in-Q
path uses outer 802.1ad VLAN 100 and inner 802.1Q VLAN 200. Checksum,
segmentation, and VLAN offloads are disabled on the disposable veth devices so
captured bytes are the bytes seen by the peer rather than pre-offload host
representations.

The verifier fails unless the retained evidence proves:

- passive interface/route enumeration and exact interface constraints;
- on-link versus gateway IPv4 decisions, routed IPv4/IPv6 sources, next hops,
  neighbor targets, and the 1280-byte MTU;
- active gateway ARP and NDP with capture ready before request transmission;
- exact Layer 2 and raw Layer 3 sends, IPv4/IPv6 matched exchanges, and no
  capture loss;
- finite live capture with independently readable PCAPNG output;
- exact Ethernet/Q-in-Q transmit evidence plus an unchanged inner datagram
  observed directly or in the peer's complete ICMP quote;
- open IPv4 TCP and IPv6 ICMP scans, plus two-hop IPv4/IPv6 traceroute;
- deterministic IPv4/IPv6 DNS responses and the hostname authorization-order
  regressions;
- one live case for each `boundary`, `random`, `bit-flip`, and `malformed`
  fuzz strategy with fixed seed, case, byte, rate, duration, and evidence
  ceilings;
- timeout plus unrelated malformed-frame evidence, low-MTU rejection, and an
  actionable unprivileged capture error; and
- injected partial-send, readiness, cleanup, overflow/loss, timeout, and
  backend-failure regressions from the same candidate source archive.

`report.json` is generated only after every semantic assertion passes. It
contains candidate identity and hashes, the topology, every passed matrix row,
and SHA-256 plus exact hexadecimal bytes for sign-off packet records. Full
typed command outputs, capture files, test logs, runner versions, and a
`SHA256SUMS` manifest remain alongside it. The workflow retains both the
directory and its compressed bundle for 90 days; record the Actions URL and
bundle digest on the release issue before marking the Linux gate complete.
