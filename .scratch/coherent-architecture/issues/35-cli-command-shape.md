# 35: One command shape

**What to build:**
- **Layout:** every command is `commands/<cmd>.rs` + `commands/<cmd>/{arguments,rendering}`. This includes the flat `dns_read`, `http`, `fragment`, `merge`, `export`, `routes`, `interfaces` and `documentation`, and `rewrite`, which has no `arguments.rs`.
- **Rendering:** the command root drives execution. `rendering.rs` only formats text from the command's output type; `capture/rendering.rs` and `replay/rendering.rs` lose their drivers. `capture` stops reaching into `read::rendering`, and shared frame text moves to `rendering/`. DNS text rendering exists once, not in three places.
- **Naming:** `output/<cmd>` is named after the command (`dns_analysis` → `dns_read`, `forwarding` → `verify_forwarding`, `scan_connect` folded into scan's output).
- **Options:** single-user `command_options` groups move into their command. Repeated fields (`max_duration_ms` ×7, `timeout_ms` ×6, `compression` ×8) become shared groups with one validation, and `--interface`/`--stream` become typed arguments.
- **Second-style commands:** they gain `//!` docs and `AFTER_LONG_HELP`, and print through the sanitizing writer instead of `write_plain_line`. Debug formatting leaves user text (`dns_read.rs`, `http.rs`), and HTTP header names are escaped.
- The copied offline scaffolding in `dns_read`/`http` becomes one helper.

Phase 4.

**Blocked by:** 34

**Status:** resolved

- [x] Every command matches the shape, and no `rendering.rs` runs a workflow.
- [x] A process test shows escape bytes in an HTTP header name or DNS name rendered safely.
- [x] `[Unreleased]` records the sanitization and argument-validation fixes.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Error codes are unchanged, and a process test pins them against ca-34
  behaviour. The shared `--max-duration-ms`/`--timeout-ms` groups define
  the argument once, and out-of-range values still reach the code that
  always rejected them: the workflow limit errors (`cli.scan_limit`,
  `cli.capture_timeout`, `cli.exchange_limit`, ...). `rewrite` keeps its
  parse-time range (`RunTime::PARSED`). Offline analysis checks the one-hour
  ceiling with `MaxDurationArgs::within_ceiling`, which takes the owner's
  error.
- Behaviour fix: offline analysis now rejects `--max-duration-ms` above one
  hour with `cli.analysis_limit`. It was unbounded before. This has its own
  changelog entry.
- `--interface`/`--stream` are typed as `Selector<InterfaceSelector>` and
  `Selector<StreamRef>`: parsed once by clap, but a malformed value is
  reported where the command reads it. So policy denial still wins over a
  malformed interface, the format check still comes first, and messages
  are unchanged. No existing tests needed edits.
- The shared groups are generic over a marker for help text and defaults (as
  `TrafficBudgetArgs` is). `--timeout-ms` defaults are text because clap's
  `default_value_t` shares one static across generic instantiations.
  `TrafficBudgetArgs` has the same latent issue; its defaults happen to match
  today.
- Core already escaped DNS names. The process test covers DNS names and TXT
  data. HTTP header names are token-only on the wire, so the header-name
  escape is defensive, and a unit test covers it.
- Hex output keeps an unstyled writer (`write_hex_line`, hex-only by
  construction). Every other text line goes through the sanitizing writer.
- Documentation has no text output. Its `rendering.rs` renders the command
  tree into completion and man files.
