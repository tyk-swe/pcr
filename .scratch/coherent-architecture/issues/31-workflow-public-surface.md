# 31: packetcraftr public surface

**What to build:** With every workflow on the client, apply the facade rule to packetcraftr:
- The `Executor`, `Authorizer`, `Selector`-style seams that the client now owns are `pub(crate)`.
- No aliases remain.
- `BoundaryError` appears in public signatures only where a caller supplies a sink; it is referenced by its core path.
- `Execution`, `Transport`, `Limits` and `Stats` each name one kind of thing.
- `lib.rs` docs describe the client model and the fixed roles.

Phase 3.

**Blocked by:** 26, 27, 28, 29, 30

**Status:** resolved

- [x] Each public item has one path, and no public name means two different things.
- [x] `scripts/check-external-consumer.py` passes.
- [x] `[Unreleased]` and the migration note are complete for phase 3.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Scope additions (decisions.md round 2 b/f and the 31 additions) are done: the executor contract,
  `policy::{Authorizer, PolicyAuthorizer, unsupported_operation}`, and `target::ResolveTarget` are
  crate-private (`PolicyAuthorizer` deleted; tests use the admission or `Policy::authorize`);
  `Clock::cancellation`/`CancellableClock` are removed; workflow (and route, neighbor, policy
  undecodable-wire) messages no longer repeat their source, with one CHANGELOG line; the stale
  Target-resolution bullet is rewritten.
- Runtime rows are unchanged (coordinator: ticket 33 consolidates them in `system/`).
- `replay::Selector` stays public (coordinator); the `capture::Selector` alias is removed and
  `SystemProviders` is a unit struct rather than an alias (`ProviderSet::system` removed).
- Beyond the ticket text: `progress` is renamed `runtime`; `dns::AttemptTransport` is
  `dns::TransportEvidence` (field `transport_evidence`); `scan::connect::Probe` is
  `connect::ProbeEvidence`; the executor trait is `execution::Step { type Evidence }` and the
  receipts are `probe::Evidence`, dns `ExchangeEvidence`, fuzz `CaseEvidence`/`CaseStep`;
  `CaptureEvidenceLimits` folds into `EvidenceLimits`.
- `BoundaryError` interpretation: it stays in public *error variants* as the crate's type-erased
  classified source (authorization, execution, output); public *function and trait signatures*
  use it only for sinks, selectors, and runtime workers. The crate refers to it by its core path.
- `BoundaryError::as_causes` in core is now public (used by the message fix).
- The fuzz fixture exchange window grew from 1 ms to 50 ms: the client fuzz tests flaked under
  load (deadline expired while preparing the exchange).
