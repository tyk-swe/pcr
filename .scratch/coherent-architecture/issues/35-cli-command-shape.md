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

**Status:** ready-for-agent

- [ ] Every command matches the shape, and no `rendering.rs` runs a workflow.
- [ ] A process test shows escape bytes in an HTTP header name or DNS name rendered safely.
- [ ] `[Unreleased]` records the sanitization and argument-validation fixes.
- [ ] fmt, clippy and the workspace tests pass.
