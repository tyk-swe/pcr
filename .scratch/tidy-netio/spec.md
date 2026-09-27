# Tidy netio architecture

Status: resolved

## Problem Statement

`coherent-architecture` (issues 17–22) gave `packetcraftr-netio` the layout
`AGENTS.md` describes: `platform/` native-only, capability → backend, one
provider shape, one deadline convention, one worker pool. A read-only audit
of the crate against those rules finds leftovers:

- Platform-neutral code still under `platform/`: the raw IP header and
  route-consistency validation in `transmit/raw_ip/preparation.rs`, and the
  capture-side interface identity check in `interface/identity.rs`, which
  calls back into the capability and then into `platform/` again.
- Redundant gates: the `native_workers` cfg always equals `native_route`;
  `any(native_route, native_send)` is `native_route`; feature lists repeat
  `dep:` entries; Windows is spelled two ways inside `platform/`.
- Backend visibility mixes `pub(super)` and `pub(in crate::platform)`, and
  some items are wider than their use.
- `capture.rs` (716 lines) mixes six responsibilities; route's contract is
  split across `models.rs`/`provider.rs` with a 16-line `route.rs`; error
  types sit in four different places; `interface::Error` classifies itself
  by cloning into `crate::Error`.
- `capture::MAX_TIMEOUT` is the workspace-wide one-hour live-wait ceiling
  (TCP connect and every workflow request use it), duplicated privately as
  `deadline::MAX_WALL_CLOCK_WAIT`. `SendEvidenceFault` is transmit-only but
  exported from the crate root.
- Group capture waits classify a spent readiness deadline and an oversized
  remainder as `cli.capture_group`, where a single session reports
  `io.capture_readiness` and `cli.capture_timeout`.
- Vocabulary drift: the reaper admits work ("reaper" is avoided for
  admission), "materialized route", "adapter" for backend, and docs that
  contradict the code (`lib.rs` "shared vocabulary at the root",
  `resources::NativeSnapshot::supported`).
- Test fixtures (`interface::Info`, `Metadata`, fake capture sources, route
  `decision()`, fake TCP providers) are copied across modules and contract
  tests.
- One behavior bug: arming a native capture source holds two pool slots
  (activation admits one, `NativeCaptureSession::spawn` another inside it),
  so the last source of a `MAX_SOURCES` group is refused while fifteen
  readers run.

## Solution

Nine independently mergeable issues, in dependency order:

1. Build gates and feature lists.
2. Platform visibility and platform docs.
3. Neutral checks out of `platform/` (raw IP validation → `transmit`,
   capture identity check → `capture::system`).
4. Capability module shape: contract-first `<cap>.rs`, private submodules
   by responsibility, `SendEvidenceFault` under `transmit`,
   `interface::Error` classifies itself.
5. One live-wait ceiling: `deadline::MAX_WAIT` replaces
   `capture::MAX_TIMEOUT` and the private duplicate.
6. Group waits classify like single-session waits.
7. Vocabulary and docs.
8. Test support convergence (`src/test_support.rs`, `tests/common/`).
9. One pool slot per native capture source: activation and reading are one
   pooled job under one permit; the reaper stops admitting.

## Constraints

- **Frozen:** machine contracts, CLI flags, exit codes, and every existing
  classification code except the two group paths in issue 6 (recorded under
  Changed).
- **Allowed:** breaking Rust API changes recorded under `[Unreleased]` and in
  `docs/migration-unreleased.md`; message text; no compatibility aliases.
- No new `build.rs` cfgs. No `target_os` outside `platform/`. No unsafe
  outside `platform/`.
- Each issue passes fmt, the five clippy profiles, and the workspace tests on
  Linux; macOS and Windows are validated by CI.

## Retained exceptions

- `platform/route.rs` (`find_interface`, `constrain_by_preferred_source`)
  and `platform/common.rs` (`os_error`, `refused`, `on_worker`) are pure but
  only a target gate says which backends use them; moving them out would
  need `target_os` outside `platform/` or dead code on one target.
- `platform/common/pcap_api.rs` is pure pcap-ABI vocabulary shared by two
  backends; it stays with the backends that speak that ABI.
- `platform/execution_context.rs` reads procfs under a Linux gate.
- `capture::Group` stays a netio composite session (issue 21 of
  `coherent-architecture`); the route family check in both crates is the
  untrusted-input boundary for injected providers.
