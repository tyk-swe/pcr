# 33: system/ is the only composition root

**What to build:**
- `system/` is the only place that constructs system providers and builds the `Client`.
- These go through it: `commands/execution.rs` (`prepare`/`Providers`), `commands/preparation.rs`, fuzz's inline copy of `execution::prepare`, replay's own transmitter/authorizer setup, and the direct `SystemProvider` construction in `routes`, `interfaces`, `capture` and `scan/connect`.
- Commands receive the composed client or providers.
- The three preparation layers (`system/route.rs`, `commands/preparation.rs`, `execution::prepare`) become one.

Phase 4.

**Blocked by:** 31, 32

**Status:** ready-for-agent

- [ ] `grep SystemProvider` outside `system/` finds nothing in the CLI.
- [ ] Live command process tests and the native-isolated tests pass.
- [ ] fmt, clippy and the workspace tests pass.
