# 24: Split probe; a crate-wide execution module

**What to build:**
- A private root `execution` module holds the crate-wide seams now in `probe`: the executor contract, evidence validation (`probe::validation`, `probe::evidence`), the pacing context (today's root `execution.rs`), and one event-sink contract (an `Event` sink running on the runtime, with the `Report` returned). DNS and fuzz import these from `execution`, not `probe`.
- `probe` keeps only the scan/traceroute kernel (runner, batch evidence, `Workflow` enum). Scan and traceroute each get their own `Error`, and `probe::Error { workflow, kind }` disappears.
- The three error-adapter traits (`target::GateErrors`, `execution::Errors`, `PacingErrors`) become one adapter trait in `execution`.
- `Errors::invalid_evidence(step, String)` takes the typed `ExchangeEvidenceError` instead of a string.
- The four `rate_delay` wrappers become one.

Phase 3.

**Blocked by:** 23

**Status:** ready-for-agent

- [ ] `probe` is imported only by scan and traceroute.
- [ ] `scan::Error` and `traceroute::Error` are re-exported from their modules. The CLI no longer imports `probe::Error`.
- [ ] Execution-context and batch-evidence tests move with the code, with no duplicates.
- [ ] fmt, clippy and the workspace tests pass.
