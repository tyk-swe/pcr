# Capability and validation matrix

These are validation routes and their scope, not a claim that this working tree
has passed them. In particular, the implementation session had no Rust toolchain
and did not exercise native networking.

| Capability | Linux | Windows / macOS |
| --- | --- | --- |
| Portable core / fake-provider contracts | Existing CI | Existing CI |
| Native profiles compile / deterministic contracts | Existing CI | Existing platform CI |
| Privileged isolated native inventory | Existing disposable namespace lane | Not configured |
| Additional passive capture smoke | Opt-in script | Opt-in script; operator-provisioned backend/driver |
| Idle cancellation, queue loss, active native I/O | Existing isolated Linux tests | No equivalent privileged CI evidence claimed |

`check-native-capture.py` requires an explicit adapter and operator confirmation:

```sh
python3 scripts/check-native-capture.py --binary PATH_TO_PACKETCRAFTR \
  --interface LOOPBACK_NAME_OR_INDEX --authorize-isolated-loopback \
  --output NEW_PRIVATE_EVIDENCE_DIRECTORY
```

It sends no traffic. It checks reported readiness, metadata, shutdown, requested
versus applied settings, a typed invalid-filter failure, and successful reopening.
Unknown effective settings remain null. Its result is `capture_smoke_passed`,
not a full native certificate. Cancellation remains explicitly `not_exercised`:
sending a signal after an arbitrary sleep does not prove capture was idle and
ready when it arrived. Use a backend-specific readiness-aware test for that claim.

## Before merge

The compact checksum-pinned decoder oracle now runs on pull requests; the larger
generated corpus remains scheduled. Its corpus checks are independent decoder
comparisons, not a verdict-semantic oracle.

Privileged review is intentionally **not** automatically enabled for arbitrary
pull requests. A maintainer reviews the source, then dispatches
`Reviewed native validation` with its full 40-character commit. The job verifies
the checkout matches that commit, does not persist checkout credentials, uses
read-only repository permissions, and runs on a disposable hosted Linux runner.

Administrators must configure required reviewers on the `native-review`
environment and decide the applicable merge protections. YAML cannot install
those protections. Do not convert this workflow to `pull_request_target`, attach
secrets to it, or run reviewed code on a persistent runner holding sensitive
network access.

The manual workflow's run is associated with the dispatch ref; inspect the
requested commit and evidence's actual commit rather than assuming its check
status attaches to an unrelated pull-request head. The existing release gate
continues requiring its exact-commit CI evidence; this workflow does not bypass it.

## Isolated Linux setup

The full workflow installs libpcap development files, `iproute2`, `util-linux`,
and `uidmap`, builds the CLI and native contract binary, and launches
`scripts/test-native-isolated.py`. The launcher creates a fresh user/network
namespace and verifies a loopback-only environment before running tests.
For sudo launches, the existing workflow maps namespace root back to the
checkout owner via explicit subordinate UID/GID entries. Reuse that setup on a
disposable runner; do not broadly change permissions on a working checkout.

The full inventory includes readiness/repeated cleanup, idle deadline and
cancellation, real bounded-queue loss, settings applied before activation,
native filter errors, interface handling, and the controlled loopback exchange.
Do not infer Windows/macOS native behavior from a Linux result or compilation.

Capture drop counters, host offloading, acquisition location, and timestamp
semantics remain contextual evidence. Zero or unavailable counters are not an
automatic completeness guarantee. The comparator deliberately avoids inferring
device loss or synchronized clocks from those observations.
