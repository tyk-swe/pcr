# 09: One pool slot per native capture source

**What to build:** Activation and reading are one pooled job under one permit. `capture/activation.rs` admits from the pool, runs `activate()` then `NativeCaptureSession::prepare`, hands the owner half over a rendezvous channel, and continues as the reader; `NativeCaptureSession::attach` builds the session from the owner half, the task, and the permit. `ReaperClient::reserve` and its pool handle go away; the reaper only transfers cleanup. A regression test with a capacity-1 pool shows one source arming and reading on one slot. `[Unreleased]` Fixed records it.

**Blocked by:** 08

**Status:** ready-for-agent

- [ ] The regression test fails before and passes after.
- [ ] All activation, session, workers, reaper, and capture contract tests pass; `native_isolated` compiles.
- [ ] fmt, clippy, and the workspace tests pass.
