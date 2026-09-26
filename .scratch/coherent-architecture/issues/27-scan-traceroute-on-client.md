# 27: Scan and traceroute on the client

**What to build:**
- Scan and traceroute become `client.scan(request, sink)` and `client.traceroute(request, sink)`.
- Pipelined execution becomes a separate capability trait instead of `Executor::execute_pipeline`'s default that fails. The duplicated capacity of 1024 is defined once.
- The scan pipeline uses the injected clock instead of `Instant::now()`.
- The scan executor no longer rebuilds a `Client` with newtype wrappers per batch (`scan/registry.rs`).
- Both modules take the fixed roles, and the `scan::Batch`/`traceroute::Batch` aliases go away.
- `ResponseClassification` and `Completion` mean one thing each, or get distinct names.
- Add a traceroute integration contract test; none exists today.

Phase 3.

**Blocked by:** 25

**Status:** resolved

- [x] The scan and scan-pipeline contract tests pass, and the new traceroute contract test passes.
- [x] A test shows the pipelined path's pacing driven by a recording clock.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- `Pipelined` has no `CAPACITY` const: the engine picks serial or pipelined from
  `max_in_flight` alone, and `scan::MAX_IN_FLIGHT` (new, public) is the one
  capacity. `probe::{PipelineOptions, PipelineEvent}` became scan-internal early
  (31 had them listed); `capability.probe_pipeline` is unreachable and removed.
- Names: scan/traceroute `ResponseClassification` -> `CorrelatedResponse`;
  `traceroute::Completion` -> `Termination` (field `termination`). `dns::*`
  untouched (26 owns it). `scan::PipelineError` -> `scan::PipelineFailure`.
- `scan::Request`/`traceroute::Request` gain `route` + `collection` and drop
  serde derives. `scan/connect.rs` test literals and `connect_scan_contracts`
  got the two fields (expect a trivial conflict with 30).
- The UDP-profile registry view is built once per scan from the request's
  profiled ports, so serial scans bind all profiled ports at once (the pipeline
  already did); "conflicting wire profiles" can no longer arise.
- Roles: `probe.rs` -> `plan/packet.rs`; `pipeline*`/`registry.rs` under
  `executor/`; `execution.rs` -> `plan.rs`; `classification.rs` -> `evidence.rs`.
- The IT that reshaped a batch through the public `Executor` seam became an
  in-crate `scan::executor` test.
