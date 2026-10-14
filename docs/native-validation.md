# Capability and validation matrix

Only retained exact-revision reports establish execution; compilation, skipped
checks, and unavailable paths never prove parity.

| Capability | Linux | macOS / Windows |
| --- | --- | --- |
| Portable/fake providers, profile compilation | CI | Platform CI |
| Privileged native inventory | Disposable loopback-only namespace lane | Reviewed host-local route; broader acceptance open |
| Readiness, cancellation, queue loss, settings, filter errors, disappearance, exchange | Eight isolated scenarios, including scoped targets | Eight-scenario inventory; record each exercised/failed/unavailable path |
| Raw IPv4 | Fixed loopback host-route delivery | `loopback_exchange`; Layer 3-only has no capture assertions |
| Raw IPv6 | Scoped namespace-local link-local TCP SYN | macOS complete-header send unsupported; Windows scoped UDP recorded |
| Scoped IPv6 | Same addresses on two isolated links; zone selects peer | Five-profile host-local `scoped_ipv6_targets` |
| Windows non-local UDP | Not claimed | No external destination tested |

`scripts/test-native-platform.py` builds CLI/test binaries per profile and runs
eight scenarios behind a UUID token/platform gate (`native_platform_evidence.py`,
v3). Unavailable reasons distinguish `unsupported_capability`,
`backend_not_installed`, `privilege_not_granted`, `isolation_unavailable`, and
`runtime_evidence_missing`.

## Before merge

PRs run the checksum-pinned decoder oracle (`scripts/check-decode-oracle.py`);
weekly adds generated input. Privileged Linux CI runs after integration, weekly,
or manually. Review the full immutable commit before dispatching
`native-platform-review.yml`; never use `pull_request_target`, checkout secrets,
or persistent sensitive runners.

## Isolated Linux setup

Install `libpcap-dev`, `iproute2`, `util-linux`, and `uidmap` on a disposable runner:

```sh
cargo build --locked --release -p packetcraftr-cli --all-features
python3 scripts/test-native-isolated.py --binary target/release/packetcraftr
```

On restricted hosts, prebuild `native_isolated` and launch under `sudo` (authorize
`root:<uid>:1` in `/etc/subuid` and `/etc/subgid` for `util-linux < 2.40`):

```sh
cargo test --locked -p packetcraftr-netio --all-features --test native_isolated --no-run
sudo python3 scripts/test-native-isolated.py --binary target/release/packetcraftr \
  --native-test-binary PATH_TO_NATIVE_ISOLATED_EXECUTABLE
```

For the five-profile scoped target-planning route, run `python3 scripts/test-target-planning-isolated.py`.

## Host discovery and OS identification

- **Host discovery (`scenario=host_discovery`):** `scripts/test-host-discovery-native.py`
  emits `discovery-native-evidence/v1` across five profiles and six dual-stack
  conditions using immediate replies and reserved closed sockets.
- **OS identification (`scenario=os_identification`):** Build the all-feature CLI
  and run `sudo python3 scripts/test-os-identification-native.py --require-complete`
  (requires `ip`, `unshare`, `nsenter`, `ethtool`). See
  [OS identification](os-identification.md).

## TCP diagnostic acceptance

Both reviewed workflows accept `scenario=tcp_diagnostics` for a clean reviewed
commit. Linux uses fresh namespaces and disposable veth peers (`ip`, `unshare`,
`nsenter`, `ethtool`, libpcap); macOS/Windows use loopback sockets and an
installed capture backend without modifying host interfaces.

```sh
sudo -n env "PATH=$PATH" "RUSTUP_HOME=$HOME/.rustup" "CARGO_HOME=$HOME/.cargo" \
  python3 scripts/test-tcp-diagnostics-native.py --reviewed-commit "$REVIEWED_COMMIT" \
  --require-complete --report target/validation/tcp-diagnostics-native.json
```

`--require-complete` requires all five profiles and supported exercised coverage
(host-local execution leaves scripted-link cases unavailable). Each invocation
bounds probes (`≤ 32`), response window (`500 ms`), operation/process duration
(`10 s`/`15 s`), and stream/capture retention (`1 MiB`), separating socket truth,
observed replies/windows, inferred states/rules, and heuristic divergences.

## SCTP and IP-protocol acceptance

Both reviewed workflows also accept `scenario=sctp_ip_protocol` via
`scripts/test-sctp-ip-protocol-native.py`
(`packetcraftr.sctp-ip-protocol-native-evidence/v1`), tracking five-profile
SCTP `init`/`cookie-echo` and IP-protocol inventory execution and typed
capability refusals.

Execution uses a fresh Linux network namespace and the independent
documentation-address Ethernet peer, with bounded SCTP chunks, CRC32c checks,
ICMP quotations, and exact retained replies checked against dataset 1.8.0.
The Linux acceptance gate requires all five profiles and all twelve unique
scenario/family/output cases per profile. macOS and Windows currently lack this
independent link fixture: execution exits nonzero and retains an
`isolation_unavailable` report. `--emit-unavailable` can record that limitation
explicitly; it cannot satisfy `--require-complete`.
