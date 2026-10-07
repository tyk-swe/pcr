# M3: Native validation on three platforms

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | None | The runtime-evidence [close gate][close-gates] of every milestone with native behavior |

PacketcraftR builds and ships for Linux, macOS, and Windows, and every roadmap
milestone requires runtime evidence on all three. Only Linux has a controlled
privileged route today: a disposable namespace lane that exercises real capture
and transmission. macOS and Windows run compilation, passive providers, and
deterministic contracts in CI, which shows the code builds and its portable
logic holds, not that a raw socket or capture device behaves as intended.

This milestone gives macOS and Windows an equivalent controlled route and makes
the difference between exercised, failed, and unavailable explicit. It adds no
scanner capability.

## Outcome

- macOS and Windows each have a controlled route that exercises privileged
  native I/O and records evidence for an exact commit.
- Every required platform/profile check reports one of exercised, failed, or
  unavailable, with a reason for the last.
- The reviewed-native and administrator-owned permission controls that protect
  the Linux lane apply to the new routes.

## Baseline

| | Linux | macOS and Windows |
| --- | --- | --- |
| Compilation and deterministic contracts | [`ci.yml`][ci] `linux` and `portable` jobs | [`ci.yml`][ci] `platforms` job on `macos-14`, `macos-15-intel`, and `windows-2022` |
| Privileged isolated native inventory | `native-isolated` job and [`native-review.yml`][native-review], through the [namespace launcher][isolated-launcher] | Not configured |
| Scenarios | Seven named in [`validation_evidence.py`][validation-evidence]: loopback exchange, readiness and repeated cleanup, idle deadline and cancellation, bounded-queue loss, settings before activation, native filter error, interface disappearance | No equivalent privileged evidence claimed |
| Evidence | `native-isolated.json`, initialized as `not_exercised` and validated for distinct namespace identifiers | None |

Known platform limits at `22c7d182d577`, from the
[project README][project-readme]: macOS does not support complete-header raw
IPv6 transmission; Windows may reject raw UDP with a non-local source; Layer 2
needs libpcap and BPF-device access on macOS and Npcap on Windows. The
[validation matrix][native-validation] is the authoritative statement of what
each route covers.

## Invariants

- Privileged validation is not automatically enabled for arbitrary pull
  requests. A maintainer reviews the source and dispatches validation for a
  full commit identifier; the job verifies the checkout matches it.
- Workflows are not converted to `pull_request_target`, do not carry secrets,
  and do not run reviewed code on a persistent runner holding sensitive network
  access.
- Required reviewers and merge protections stay administrator-owned; YAML does
  not install them.
- No scenario uses an external destination.
- A Linux result or a successful compilation is never evidence of macOS or
  Windows native behavior.

## Scope

### M3.1 macOS privileged lane

A controlled route that runs the native scenario inventory on macOS with the
privileges that Layer 2 capture/injection and raw Layer 3 transmission need.
Scenarios that depend on an unsupported capability, such as complete-header raw
IPv6 transmission, report unavailable with that reason.

### M3.2 Windows privileged lane

A controlled route that runs the native scenario inventory on Windows with
administrator rights and, for Layer 2 scenarios, a working capture driver.
Raw-source restrictions are recorded as the capability limits they are.

### M3.3 Evidence reporting

- Each required platform/profile check reports **exercised**, **failed**, or
  **unavailable**. Unavailable carries the reason: capability unsupported,
  privilege not granted, or backend not installed.
- Evidence names the platform, profile, and exact commit, and is preserved on
  failure, as the Linux lane's evidence is today.
- Compilation and fake-provider results are reported as what they are and are
  never relabeled as privileged native evidence.
- Missing runtime evidence remains an open platform gap in the
  [gap matrix][matrix] and in the [validation matrix][native-validation].

## Change map

| Change | Start here |
| --- | --- |
| CI routes | [`ci.yml`][ci] (`platforms`, `native-isolated`), [`native-review.yml`][native-review] |
| Scenario launcher | [`scripts/test-native-isolated.py`][isolated-launcher] |
| Scenario inventory and evidence checks | [`scripts/validation_evidence.py`][validation-evidence], [`scripts/check-release-evidence.py`][release-evidence] |
| Native contract executable | [`tests/native_isolated.rs`][native-isolated-test] |
| Capability selection | netio [`build.rs`][native-build], [`platform/dispatch.rs`][native-dispatch] |
| Published route coverage | [`docs/native-validation.md`][native-validation] |

## Decisions to settle

1. Hosted or self-hosted runners for the privileged routes (recommended:
   disposable hosted runners where they grant the needed privilege, because the
   current guidance forbids persistent runners with sensitive network access).
2. The isolation each platform uses in place of a Linux network namespace
   (recommended: begin with loopback-only scenarios behind a refusal check
   equivalent to the launcher's namespace check, and report any scenario that
   cannot be isolated as unavailable).
3. How the Windows capture driver is provisioned on a runner, including whether
   its license terms permit automated installation (recommended: settle the
   terms first; until then Windows Layer 2 scenarios report unavailable).
4. Whether evidence extends the current format or takes a new version
   (recommended: a new evidence version with a platform field, because the
   current validator requires namespace identifiers only Linux has).
5. Which scenarios are required per platform and profile (recommended: the
   existing seven wherever the capability exists, with each omission recorded
   and justified).

## Decisions made

1. **Disposable hosted runners** run the manual
   `.github/workflows/native-platform-review.yml` route, which requires an
   exact reviewed commit and the reviewed-native permission control; there are
   no persistent privileged runners.
2. **Host-local only, not namespace parity.** The admitted destinations are
   the literal `127.0.0.1` and scoped IPv6 addresses already assigned to the
   host (preferring loopback where available), behind a
   token plus platform gate (`native_loopback.rs`); the macOS/Windows firewall
   boundary is a boundary of its own, documented as different isolation from
   Linux namespaces — scenarios it cannot host report unavailable, never a
   weaker claim.
3. **No driver provisioning without specific license approval.** Windows
   Layer 2 stays unavailable where Npcap is not already installed; no
   automatic driver download or install runs on the route.
4. **Evidence format v3 is separate.** `scripts/native_platform_evidence.py`
   validates the v3 host-local record (platform, profile, per-scenario
   exercised/failed/unavailable); the Linux netns v1 evidence remains its own
   release gate.
5. **All eight scenarios in every profile.** `native_loopback.rs` declares
   exactly the authored inventory, each either exercised or marked with a
   precise `reason_code`; feature-disabled profiles map to
   `unsupported_capability`, absent backends to `backend_not_installed`, and
   interface mutation to `isolation_unavailable`.

## Exit criteria

- [ ] macOS has a controlled route that runs the native scenario inventory for
      an exact commit and preserves its evidence.
- [ ] Windows has a controlled route that runs the native scenario inventory
      for an exact commit and preserves its evidence.
- [ ] Required platform/profile checks distinguish exercised, failed, and
      unavailable scenarios.
- [ ] Compilation and fake-provider results are never relabeled as privileged
      native evidence.
- [ ] The reviewed-native and administrator-owned permission controls are
      preserved on every route.
- [ ] Missing runtime evidence is still listed as an open platform gap wherever
      a scenario is unavailable.
- [ ] The [validation matrix][native-validation] states what each new route
      covers.

## Notes

The reviewed-native route, scenario executable (`native_loopback.rs`), and
validators are implemented. [M4 acceptance records](evidence/m04/README.md)
now prove the scoped IPv6 scenario across five profiles on Linux, macOS
ARM/Intel, and Windows for clean revision
`8e010a0b9eac118aa13384f0b854111a73d47d76`. Focused host reports deliberately
leave the other seven scenarios unexecuted. The broader macOS/Windows native
inventory, interface-isolation evidence, and administrator-owned protection
controls remain incomplete, so M3 stays **In progress**.

[M6][m6-limits] found an open question for native scan evidence on Linux. Over
an isolated veth pair, kernel replies (SYN/ACK, RST, ICMP port unreachable)
arrive about 30 µs after a probe, before `send()` returns. The shared rule that
a capture inside the submission interval is not proven post-send discards
them, so those raw scan endpoints read as silent. Slower replies correlate
normally. Native scan scenarios here need to decide what such frames prove
before claiming TCP or ICMP-error coverage.

[close-gates]: README.md#close-gates
[matrix]: nmap-gap-matrix.md
[m6-limits]: m06-port-planning-inference.md#known-limits
[project-readme]: ../../README.md
[native-validation]: ../native-validation.md
[ci]: ../../.github/workflows/ci.yml
[native-review]: ../../.github/workflows/native-review.yml
[isolated-launcher]: ../../scripts/test-native-isolated.py
[validation-evidence]: ../../scripts/validation_evidence.py
[release-evidence]: ../../scripts/check-release-evidence.py
[native-isolated-test]: ../../crates/packetcraftr-netio/tests/native_isolated.rs
[native-build]: ../../crates/packetcraftr-netio/build.rs
[native-dispatch]: ../../crates/packetcraftr-netio/src/platform/dispatch.rs
