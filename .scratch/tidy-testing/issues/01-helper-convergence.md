# 01: Converge integration helper directories on tests/common/

**What to build:** `git mv crates/packetcraftr/tests/support crates/packetcraftr/tests/common` and `git mv crates/packetcraftr-cli/tests/support crates/packetcraftr-cli/tests/common`, then update every `mod support;` / `use support::` reference to `common`. `packetcraftr-core` already uses `tests/common/`.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] `packetcraftr/tests/support/` moved to `tests/common/` (mod.rs).
- [x] `packetcraftr-cli/tests/support/` moved to `tests/common/` (mod.rs, process.rs, stats_report.rs, tls_capture.rs).
- [x] All `mod support;` and `use support::` references updated.
- [x] fmt, clippy, and workspace tests pass.
