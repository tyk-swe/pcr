# Capability and validation matrix

Routes describe scope, not a passing commit. Only retained exact-revision reports
establish execution; skipped/unavailable paths never prove parity.

| Capability | Linux | macOS / Windows |
| --- | --- | --- |
| Portable/fake providers, profile compilation | CI | Platform CI |
| Privileged native inventory | Disposable loopback-only namespace lane | Reviewed host-local route; broader acceptance open |
| Readiness, cancellation, queue loss, settings, filter errors, disappearance, exchange | Eight isolated scenarios, including scoped targets | Eight-scenario inventory; record each exercised/failed/unavailable path |
| Raw IPv4 | Fixed loopback host-route delivery | loopback_exchange; Layer 3-only has no capture assertions |
| Raw IPv6 | Scoped namespace-local link-local TCP SYN only | macOS complete-header send unsupported; Windows scoped UDP recorded; other paths unverified |
| Scoped IPv6 | Same addresses on two isolated links; zone selects list/connect/raw peer | [M4 five-profile records](roadmap/evidence/m04/README.md): enumeration, aliases, sockets, pinned raw route, local UDP or explicit capability failure |
| Windows non-local UDP | Not claimed | No external destination tested |

`scripts/test-native-platform.py` builds CLI/test binaries per profile, retains
digests, and runs eight scenarios behind UUID token/platform admission.
Host-local evidence v3 (`native_platform_evidence.py`) is separate from Linux
netns v1. Unavailable reason codes distinguish unsupported_capability,
backend_not_installed, privilege_not_granted, isolation_unavailable, and
runtime_evidence_missing. Compilation is never runtime evidence.

Scoped host fixtures use already assigned addresses, preferring loopback; no
interface mutation/external peer. Windows names outside token grammar use IPv6
index aliases while retaining full identity. Scoped_paths distinguishes selection,
sockets, and raw transmission; missing IPv6 is unavailable, not a passing refusal.
`--scenario scoped_ipv6_targets` leaves seven unrelated scenarios unexercised.

## Before merge

PRs run the compact checksum-pinned decoder oracle; weekly adds generated input.
It compares decoded fields, not verdict semantics. Privileged Linux CI runs only
after integration, weekly, or manually, not arbitrary PRs.

Review the source before dispatching Reviewed native validation or
`native-platform-review.yml` with its full immutable commit. Jobs verify checkout,
use read-only permissions/disposable runners, do not persist checkout credentials,
and retain failures. Inspect evidence's actual commit: dispatch-ref status is not
an unrelated PR-head check or a substitute for release exact-commit CI.

Administrators configure native-review required reviewers/merge protections.
YAML cannot install them. Never use pull_request_target, secrets, or persistent
runners with sensitive access for these routes.

## Isolated Linux setup

Install libpcap-dev, iproute2, util-linux, and uidmap on a disposable runner:

```sh
cargo build --locked --release -p packetcraftr-cli --all-features
python3 scripts/test-native-isolated.py --binary target/release/packetcraftr
```

The launcher builds native_isolated (or takes --native-test-binary), reexecutes
in fresh user/network namespaces, and requires parent-distinct, loopback-only
isolation before scenarios. Local dummy/veth interfaces are created/deleted;
no external destination is used. Report defaults to target/native-isolated.json.

For restricted hosts, prebuild and launch under sudo, as CI does:

```sh
cargo test --locked -p packetcraftr-netio --all-features --test native_isolated --no-run
sudo python3 scripts/test-native-isolated.py --binary target/release/packetcraftr \
  --native-test-binary PATH_TO_NATIVE_ISOLATED_EXECUTABLE
```

Use the executable path printed by --no-run. Namespace root maps to the checkout
owner, without relaxing host policy/permissions. util-linux<2.40 uses
newuidmap/newgidmap: authorize that UID/GID for root in /etc/subuid and /etc/subgid
(e.g. root:1001:1); newer versions map directly. Never broadly chmod the checkout.

The scoped scenario gives two links the same fe80::1/fe80::2 pair: only zone
selects the peer. One link has a connect listener; packet-socket raw SYN response
to static-neighbor fe80::3 uses a historical short delay. That fixture is not
undelayed fast-reply acceptance; M5 provides the immediate-response inventory.

For M4's five-profile scoped-only route:

```sh
python3 scripts/test-target-planning-isolated.py
```

Start clean. Portable must refuse scoped capabilities; default/pcap-free exercise
list/connect but refuse capture-backed raw scan. Layer 2 selects layer2; full
native also delivers/correlates raw probes. Reports retain commands, outputs,
binary/driver digests, fixtures, and provenance; seven M3 scenarios stay unexercised.
On restricted disposable hosts preserve PATH/RUSTUP_HOME/CARGO_HOME through sudo
because the launcher builds before entering namespaces.

## Host discovery

`scripts/test-host-discovery-native.py` owns separate discovery-native-evidence/v1.
Both reviewed workflows accept scenario=host_discovery at a clean exact commit.
Five-profile reports retain source/corpus/binary identity, commands/output,
fixture targets, actual privilege/isolation, and case outcomes.

Linux fresh namespaces use documentation-address veth links and independently
encoded immediate replies. Six dual-stack conditions are responsive, closed,
silent, router-blocked, routed, and shared-link, through discovery-only and both
follow-up strategies. Router errors must be retained, not only no_response.
Ordinary socket refusal uses reserved closed ports.

Host-local macOS/Windows permits no interface mutation, remote traffic, external
DNS, or driver installation. Missing dependencies/raw support/routed isolation
remain unavailable. Require-complete fails missing coverage; disabled profiles
count refusals only with actual typed nonzero results.
[M5 commands/limits](roadmap/m05-host-discovery.md#independent-discovery-corpus-and-runtime-route)
and [Linux acceptance](roadmap/evidence/m05/README.md) retain five profiles.
Broader macOS/Windows acceptance remains open, including historical failures/skips.

Drop counters, offloading, capture point, and timestamps remain contextual;
zero/unknown drops do not establish completeness, device loss, or synchronized clocks.

## OS identification

Build the all-feature CLI, then run
`sudo python3 scripts/test-os-identification-native.py --require-complete`.
Linux requires `ip`, `unshare`, `nsenter`, and `ethtool`; the runner enters a fresh
parent-distinct network namespace and a separate peer namespace, creates only a
documentation-address veth pair, and disables checksum offload. It preserves
source/binary/corpus identity and actual JSON/NDJSON outputs for dual-stack
suitable and missing-prerequisite cases. No remote targets or DNS are used.

The reviewed macOS/Windows workflow exposes `os_identification`. Its host-local
loopback cases install no drivers and change no interfaces. Unsupported,
unavailable, and failed paths remain explicit; loopback execution does not close
isolated routed/shared-link acceptance. Original training and independent-kernel
hold-out evidence are described in [M10 evidence](roadmap/evidence/m10/README.md).
Broader M10 exact reviewed-revision/platform acceptance remains open.

## M12 TCP diagnostic acceptance

Both reviewed workflows accept `scenario=tcp_diagnostics`. Use a full reviewed
commit whose clean checkout includes the runner. Linux requires existing root
privileges plus `ip`, `unshare`, `nsenter`, `ethtool`, and libpcap. It creates only
fresh network namespaces and disposable documentation-address veth peers.
macOS/Windows use literal loopback sockets, existing administrator/root privileges,
and an already installed capture backend; the runner does not install drivers or
modify host interfaces. A non-listening bound socket reserves the closed fixture
port independently of scanner output; SYN controls verify both socket conditions.

```sh
sudo -n env "PATH=$PATH" "RUSTUP_HOME=$HOME/.rustup" "CARGO_HOME=$HOME/.cargo" \
  python3 scripts/test-tcp-diagnostics-native.py --reviewed-commit "$REVIEWED_COMMIT" \
  --require-complete --report target/validation/tcp-diagnostics-native.json
```

`REVIEWED_COMMIT` is the full reviewed SHA, not a branch name. `--profiles` selects
an ordered subset for investigation; `--require-complete` requires all five
profiles and supported exercised coverage. `--emit-unavailable
runtime_evidence_missing` initializes the complete inventory before builds.
Host-local execution leaves isolated scripted-link cases unavailable and therefore
cannot pass `--require-complete`. Actual typed capability refusals in disabled
profiles remain refusal checks, rather than exercised scans.

Each invocation permits at most 32 probes, a 500 ms response window, 10 seconds of
operation duration, 15 seconds of process duration, and 1 MiB per output stream or
capture retention domain. Fixtures and independent watchers have finite frame,
readiness, and cleanup bounds. Reports retain build diagnostics, commands and
failures, exact source/corpus/binary digests, kernel/backend/isolation, independent
wire bytes/timestamps, socket provision, output observations, and cleanup.
JSON and NDJSON are checked through output/v15 without changing that interface.

ACK unfiltered and FIN-family open-or-filtered results are not socket truth.
Window and FIN-family disagreement with a known listener or closed socket is a
recorded heuristic divergence for conflicting open/closed claims. Ambiguous and
path states remain observations. Incorrect bytes, correlation, rule application,
partitions, missing positive evidence, or loss is a failure. Reports remain
revision-bound artifacts, and adding the runner closes no broader platform,
routed/middlebox, or operating-system accuracy gate.
