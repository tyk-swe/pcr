# 33: system/ is the only composition root

**What to build:**
- `system/` is the only place that constructs system providers and builds the `Client`.
- These go through it: `commands/execution.rs` (`prepare`/`Providers`), `commands/preparation.rs`, fuzz's inline copy of `execution::prepare`, replay's own transmitter/authorizer setup, and the direct `SystemProvider` construction in `routes`, `interfaces`, `capture` and `scan/connect`.
- Commands receive the composed client or providers.
- The three preparation layers (`system/route.rs`, `commands/preparation.rs`, `execution::prepare`) become one.

Phase 4.

**Blocked by:** 31, 32

**Status:** resolved

- [x] `grep SystemProvider` outside `system/` finds nothing in the CLI.
- [x] Live command process tests and the native-isolated tests pass.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- The three layers are one module, `system/preparation.rs` (`prepare_live` for send/exchange,
  `prepare_plan`, and `prepare_workflow` for dns/scan/traceroute and live fuzz). `system/route.rs`
  is its private helper. `commands/execution.rs` keeps only the `run_workflow` driver.
- Fuzz and replay (C3): fuzz's inline copy now calls `prepare_workflow` before the recipe is read and
  composes its client afterwards. Replay had no transmitter/authorizer setup left, so it only takes its
  client from `system::client` with `Runtime::Client`.
- Runtime rows (C2): `system::Runtime` is the one table of published names. dns, scan, and traceroute
  register only `workflow_progress`, and the idle `client_progress` row is gone. The CHANGELOG "Changed"
  entry replaces the unreleased DNS `client_progress` line. Other commands' rows are unchanged
  (checked with a worker-row harness against the pre-33 tip).
- C7: `InterfaceSelector::matches` is removed, and selection uses `route::Interface::matches`.
  The `interfaces` selection unit tests moved to `system/interface.rs` with `select_interfaces`.
- Command unit tests build fake-provider clients through the `#[cfg(test)]` `system::fixture`.
- C6: `native_isolated.rs` is netio-only and this change does not affect it. It needs user
  namespaces, so the CI launcher is authoritative. The local workspace run passes.

