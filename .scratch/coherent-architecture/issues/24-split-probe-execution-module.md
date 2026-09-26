# 24: Split probe; a crate-wide execution module

**What to build:**
- A private root `execution` module holds the crate-wide seams now in `probe`: the executor contract, evidence validation (`probe::validation`, `probe::evidence`), the pacing context (today's root `execution.rs`), and one event-sink contract (an `Event` sink running on the runtime, with the `Report` returned). DNS and fuzz import these from `execution`, not `probe`.
- `probe` keeps only the scan/traceroute kernel (runner, batch evidence, `Workflow` enum). Scan and traceroute each get their own `Error`, and `probe::Error { workflow, kind }` disappears.
- The three error-adapter traits (`target::GateErrors`, `execution::Errors`, `PacingErrors`) become one adapter trait in `execution`.
- `Errors::invalid_evidence(step, String)` takes the typed `ExchangeEvidenceError` instead of a string.
- The four `rate_delay` wrappers become one.

Phase 3.

**Blocked by:** 23

**Status:** resolved

- [x] `probe` is imported only by scan and traceroute.
- [x] `scan::Error` and `traceroute::Error` are re-exported from their modules. The CLI no longer imports `probe::Error`.
- [x] Execution-context and batch-evidence tests move with the code, with no duplicates.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Wire correlation (`observe`, identity and ephemeral-port helpers) and
  `Transport` moved to a private `correlation` module (decision 9); `probe`
  stays public as the home of `Transport`, `ProbeEndpoint`, and `ProbeStatus`
  and, per decision f, still re-exports the executor contract.
- The family miss is not an adapter method: fuzz implements the adapter and
  can never raise it. It travels with the declared family as
  `target::FamilyGate`. Replay only paces, so `execution::pause` returns a
  typed `Paused` that replay names itself instead of implementing the adapter.
  The adapter gained `invalid_limit`, which the one `execution::rate_delay`
  uses. Connect scan and the scan pipeline keep their own rate checks because
  their errors differ.
- `ExchangeEvidenceError` is public at the crate root under its ticket name, so
  it does not clash with `dns::EvidenceError` (renamed in 26).
- `probe::Workflow` is crate-private and only picks evidence diagnostics and
  the wording of evidence errors.
- The sink contract is `packetcraftr::Sink<E>` with an `Ack` answer type;
  `progress::Sink` became `progress::Worker<T, A = ()>`, and exchange events
  also go through `execution::publisher`. `Discard` was not added: nothing
  uses it yet.

