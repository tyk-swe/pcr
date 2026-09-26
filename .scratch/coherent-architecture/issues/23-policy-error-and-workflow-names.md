# 23: One policy error, budget names, and Stats

**What to build:**
- **Policy:** policy returns one `policy::Error`. `Policy::authorize` and `policy/wire.rs` stop returning `crate::Error`, so `crate::Error` and `policy::Error` no longer wrap each other. `UnsupportedOperation` moves into `policy::Error`.
- **Limit and Budget names** in packetcraftr: configured policy ceilings are `…Limits`, running allowances are `…Budget`. This covers `evidence::Budget` (retention budget), the private `preparation::Budget`, `policy::{Wire,Socket,Capture}Budget` and `dns::plan::OperationBudget`, each classified by the rule.
- **Stats:** `Stats` is the one word workspace-wide: netio `capture::Statistics` and `scan::connect::Statistics` are renamed, and serde keeps their JSON names.
- **Duration ceilings:** `MAX_DURATION`, `MAX_REPLAY_DURATION`, `MAX_SEND_DURATION` and `MAX_EXCHANGE_TIMEOUT` are all netio `MAX_TIMEOUT`, so they become one reference.

Phase 3.

**Blocked by:** 22

**Status:** ready-for-agent

- [ ] Policy has one error type, and nothing circular remains between `crate::Error` and `policy::Error`.
- [ ] Every Budget or Limit name matches `CONTEXT.md`.
- [ ] Output/v6 conformance passes unchanged.
- [ ] `[Unreleased]` and the migration note list the renames.
- [ ] fmt, clippy and the workspace tests pass.
