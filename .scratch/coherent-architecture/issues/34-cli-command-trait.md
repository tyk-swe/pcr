# 34: One command trait and one command enum

**What to build:**
- Each command implements one command trait declaring its kind, output formats, publication duration, cancellation support, preset membership and resource stages. The facts come from `kind()`, `publication_duration()`, `supports_cancellation()`, `contract.rs` formats, `presets.rs` and `resources.rs`.
- Dispatch, the contract, presets and resources read from the trait. The clap `Command` enum and `output::contract::Command` become one enum.
- `resources.rs` and `presets.rs` read typed arguments instead of clap argument-id strings (`max_tcp_`, `_ms` prefixes), and no longer recompile forwarding rules and filters to decide which stages are enabled.
- The offline-command list exists once.
- `documentation` is dispatched like the other commands, removing the `unreachable!`.

Phase 4.

**Blocked by:** 32

**Status:** ready-for-agent

- [ ] Adding a command means one trait impl plus one enum variant.
- [ ] Preset and resource-diagnostics process tests pass unchanged.
- [ ] fmt, clippy and the workspace tests pass.
