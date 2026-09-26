# 34: One command trait and one command enum

**What to build:**
- Each command implements one command trait declaring its kind, output formats, publication duration, cancellation support, preset membership and resource stages. The facts come from `kind()`, `publication_duration()`, `supports_cancellation()`, `contract.rs` formats, `presets.rs` and `resources.rs`.
- Dispatch, the contract, presets and resources read from the trait. The clap `Command` enum and `output::contract::Command` become one enum.
- `resources.rs` and `presets.rs` read typed arguments instead of clap argument-id strings (`max_tcp_`, `_ms` prefixes), and no longer recompile forwarding rules and filters to decide which stages are enabled.
- The offline-command list exists once.
- `documentation` is dispatched like the other commands, removing the `unreachable!`.

Phase 4.

**Blocked by:** 32

**Status:** resolved

- [x] Adding a command means one trait impl plus one enum variant.
- [x] Preset and resource-diagnostics process tests pass unchanged.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- One declaration, two generated types: `commands!` in `commands.rs` lists each
  command once and generates both the clap `Command` enum and its published
  discriminant, re-exported as `output::contract::Command`. A payload-carrying
  clap enum cannot also be the `Copy` serialized identifier. Keeping the public
  path also avoids changing about 250 call sites and tests. The kind comes from
  the variant's published name in the declaration, not from a trait constant.
  `Command::ALL` is now in `--help` order.
- `documentation` has no contract, so it has no `Spec` impl. It goes through
  the same generated `Command::start` as every other command, and
  `Launch::generate` runs it.
- Presets still apply their values as clap defaults keyed by argument id,
  which keeps clap validation and value-source tracking. Membership now comes
  from `Spec::OFFLINE`, and only the selected subcommand is rewritten.
- Resource settings are declared per typed field (`resources::declare!`).
  verify-forwarding reports whether it needs the stream index once its rules
  and filters compile (`resources::stream_index_needed`). Before that, the
  indexed stages count as enabled. One edge case changed: if decode setup
  fails before the rules compile, the error now reports them enabled.
- Checked with a before/after harness: `--resource-diagnostics` output for all
  26 commands (39 invocations, including presets, NDJSON, and
  verify-forwarding index cases) is byte-identical.
