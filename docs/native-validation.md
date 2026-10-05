# Capability and validation matrix

These are validation routes and their scope. Listing a route is not evidence
that a particular commit passed it; that evidence is the recorded CI,
reviewed-native, or release report.

| Capability | Linux | Windows / macOS |
| --- | --- | --- |
| Portable core / fake-provider contracts | CI | CI |
| Native profiles compile / deterministic contracts | CI | Platform CI |
| Privileged isolated native inventory | Disposable namespace lane | Manual reviewed-native route (`native-platform-review.yml`, disposable hosted runners, exact commit) |
| Idle cancellation, queue loss, active native I/O | Isolated Linux tests | `native_loopback.rs` seven-scenario inventory, pending recorded runs |
| Raw IPv4 delivery, Layer 3 | Isolated Linux tests (fixed `127.0.0.1` host route) | Host loopback `loopback_exchange` (no Layer 2 in `native-layer3`-only profiles; capture assertions are Layer 2–gated) |
| Raw IPv6 | Not covered by this inventory — the isolated suite exercises IPv4 loopback only | Unsupported on the macOS host route; unexercised elsewhere — the gap is recorded, not fabricated |
| Windows non-local UDP | Not claimed | Unchanged: no non-local UDP destinations on the host route |

`scripts/test-native-platform.py` is the launcher: it compiles the CLI and the
`native_loopback` test binary under each feature profile, records both
digests, admits a UUID token plus platform gate, and runs each of the seven
scenarios once per profile. Compilation is never reported as native evidence;
each scenario is `exercised`, `failed`, or `unavailable` with a precise
`reason_code` (`unsupported_capability`, `backend_not_installed`,
`privilege_not_granted`, `isolation_unavailable`, `runtime_evidence_missing`).
Evidence uses the v2 host-loopback record validated by
`scripts/native_platform_evidence.py`; the Linux netns v1 record remains its
own release gate.

## Before merge

The compact checksum-pinned decoder oracle runs on pull requests; the weekly run
adds the larger generated corpus. Its corpus checks are independent decoder
comparisons, not a verdict-semantic oracle.

Privileged review is intentionally **not** automatically enabled for arbitrary
pull requests: the `ci.yml` isolated lane runs after integration, weekly, and on
manual dispatch, never on a pull request. A maintainer reviews the source, then
dispatches `Reviewed native validation` with its full 40-character commit. The
job verifies the checkout matches that commit, does not persist checkout
credentials, uses read-only repository permissions, and runs on a disposable
hosted Linux runner.

Administrators must configure required reviewers on the `native-review`
environment and decide the applicable merge protections. YAML cannot install
those protections. Do not convert this workflow to `pull_request_target`, attach
secrets to it, or run reviewed code on a persistent runner holding sensitive
network access.

The manual workflow's run is associated with the dispatch ref; inspect the
requested commit and evidence's actual commit rather than assuming its check
status attaches to an unrelated pull-request head. The release gate requires
its own exact-commit CI evidence; this workflow does not bypass it.

## Isolated Linux setup

The isolated lane needs libpcap development files, `iproute2`, `util-linux`, and
`uidmap`. Build the full-native CLI and run the launcher:

```sh
cargo build --locked --release -p packetcraftr-cli --all-features
python3 scripts/test-native-isolated.py --binary target/release/packetcraftr
```

The launcher builds the ignored `native_isolated` test target (unless
`--native-test-binary` names a prebuilt one) and re-executes itself in a fresh
user/network namespace. It refuses to run any scenario unless that namespace
differs from its parent and holds only loopback; no external destinations are
used, and the interface-disappearance scenario creates and deletes a
namespace-local dummy interface. It writes its evidence to
`target/native-isolated.json` (`--report`).

On restricted hosts, prebuild the test executable and run the launcher under
`sudo` with `--native-test-binary`, as `ci.yml` does:

```sh
cargo test --locked -p packetcraftr-netio --all-features --test native_isolated --no-run
sudo python3 scripts/test-native-isolated.py --binary target/release/packetcraftr \
  --native-test-binary PATH_TO_NATIVE_ISOLATED_EXECUTABLE
```

`--no-run` prints the executable's path. For a `sudo` launch, the launcher maps
namespace root to the invoking checkout owner's UID and GID; it does not relax
host namespace policy or file permissions. On util-linux before 2.40 that mapping is applied by
`newuidmap`/`newgidmap`, so authorize the owner's UID and GID for root in
`/etc/subuid` and `/etc/subgid` (for example `root:1001:1`); newer util-linux
writes the mapping directly and needs no subid entry. Do this on a disposable
runner; do not broadly change permissions on a working checkout.

The inventory covers readiness/repeated cleanup, idle deadline and
cancellation, real bounded-queue loss, settings applied before activation,
native filter errors, interface disappearance, and the controlled loopback
exchange. Do not infer Windows/macOS native behavior from a Linux result or
compilation.

Capture drop counters, host offloading, acquisition location, and timestamp
semantics remain contextual evidence. Zero or unavailable counters are not an
automatic completeness guarantee. The comparator deliberately avoids inferring
device loss or synchronized clocks from those observations.
