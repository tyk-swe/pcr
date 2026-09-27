# 08: Test support convergence

**What to build:** `src/test_support.rs` (interface and capture metadata builders) and `capture/live/test_support.rs` (fake sources and interrupts) replace copied fixtures; `tests/common/mod.rs` holds `decision()` and the fake TCP provider; transmit tests move from `model_contracts.rs` to `transmit_contracts.rs` (missing-layer tests in a gated submodule); the tcp test in `deadline_contracts.rs` moves to `tcp_pending_contracts.rs`; the duplicated detach unit test is dropped.

**Blocked by:** 07

**Status:** ready-for-agent

- [ ] No fixture builder is defined twice in the crate.
- [ ] fmt, clippy, and the workspace tests pass.
