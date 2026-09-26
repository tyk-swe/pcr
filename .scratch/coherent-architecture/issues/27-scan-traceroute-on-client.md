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

**Status:** ready-for-agent

- [ ] The scan and scan-pipeline contract tests pass, and the new traceroute contract test passes.
- [ ] A test shows the pipelined path's pacing driven by a recording clock.
- [ ] fmt, clippy and the workspace tests pass.
