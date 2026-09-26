# 23: One policy error, budget names, and Stats

**What to build:**
- **Policy:** policy returns one `policy::Error`. `Policy::authorize` and `policy/wire.rs` stop returning `crate::Error`, so `crate::Error` and `policy::Error` no longer wrap each other. `UnsupportedOperation` moves into `policy::Error`.
- **Limit and Budget names** in packetcraftr: configured policy ceilings are `…Limits`, running allowances are `…Budget`. This covers `evidence::Budget` (retention budget), the private `preparation::Budget`, `policy::{Wire,Socket,Capture}Budget` and `dns::plan::OperationBudget`, each classified by the rule.
- **Stats:** `Stats` is the one word workspace-wide: netio `capture::Statistics` and `scan::connect::Statistics` are renamed, and serde keeps their JSON names.
- **Duration ceilings:** `MAX_DURATION`, `MAX_REPLAY_DURATION`, `MAX_SEND_DURATION` and `MAX_EXCHANGE_TIMEOUT` are all netio `MAX_TIMEOUT`, so they become one reference.

Phase 3.

**Blocked by:** 22

**Status:** resolved

- [x] Policy has one error type, and nothing circular remains between `crate::Error` and `policy::Error`.
- [x] Every Budget or Limit name matches `CONTEXT.md`.
- [x] Output/v6 conformance passes unchanged.
- [x] `[Unreleased]` and the migration note list the renames.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- The limits-only shape `Operation::Budgeted` is `Operation::Wire`, so `Operation::shape()` reports `"wire"` and the `internal.unsupported_operation` message changes with it.
- `policy::Error` has no I/O variant. `authorize_built_wire` is gone: preparation takes the wire link type from the crate-private `route::Plan::wire_link_type()`, which still reports netio `UnresolvedLinkMode`.
- The duration ceilings reference netio `capture::MAX_TIMEOUT` directly. No new packetcraftr constant, to avoid a second public path.
- Running allowances keep `Budget`: `CaptureBudget`, preparation's private `Budget`, and progress's `WorkerBudget`. `evidence::Budget` is now `RetentionBudget`. The CLI's `TrafficBudgetArgs`/`PacketBudgetArgs` flag groups are outside packetcraftr and unchanged.
- Stats: the types, the `Session::stats()` accessor, and the CLI output mirrors are renamed. Error variants (`StatisticsOverflow`, `InvalidCaptureStatistics`, `IncompleteStatistics`, `capture::Cause::Statistics`) and serialized `statistics` fields keep their names. Tickets 26–31 reshape those errors.
- Messages and remediation text are unchanged, including `LimitOverflow`'s "operation traffic budget overflowed".
