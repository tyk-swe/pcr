# 08: Test support convergence

**What to build:** `src/test_support.rs` (interface and capture metadata builders) and `capture/live/test_support.rs` (fake sources and interrupts) replace copied fixtures; `tests/common/mod.rs` holds `decision()` and the fake TCP provider; transmit tests move from `model_contracts.rs` to `transmit_contracts.rs` (missing-layer tests in a gated submodule); the tcp test in `deadline_contracts.rs` moves to `tcp_pending_contracts.rs`; the duplicated detach unit test is dropped.

**Blocked by:** 07

**Status:** resolved

- [x] No fixture builder is defined twice in the crate.
- [x] fmt, clippy, and the workspace tests pass.

## Comments

- `tests/common/mod.rs` holds only the route `decision` fixture; the TCP test that duplicated a fake provider moved next to the pending-connect fixtures instead of growing a second shared one.
- The always-compiled `interface::validation` tests use the shared `assigned`/`v4` builders, which keeps `test_support` free of dead code in the portable profile.
