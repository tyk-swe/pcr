# 09: One pool slot per native capture source

**What to build:** Activation and reading are one pooled job under one permit. `capture/activation.rs` admits from the pool, runs `activate()` then `NativeCaptureSession::prepare`, hands the owner half over a rendezvous channel, and continues as the reader; `NativeCaptureSession::attach` builds the session from the owner half, the task, and the permit. `ReaperClient::reserve` and its pool handle go away; the reaper only transfers cleanup. A regression test with a capacity-1 pool shows one source arming and reading on one slot. `[Unreleased]` Fixed records it.

**Blocked by:** 08

**Status:** resolved

- [x] The regression test fails before and passes after.
- [x] All activation, session, workers, reaper, and capture contract tests pass; `native_isolated` compiles.
- [x] fmt, clippy, and the workspace tests pass.

## Comments

- Reproduced on the previous code by holding 15 of the shared pool's 16 slots and arming one source through `capture::activation::open`: it failed with "native capture cleanup capacity 16 is exhausted". The same scenario on the new code arms the source with the pool at 16 active. That check ran once, alone, because it occupies the process-wide pool; the committed regression test uses a private one-slot pool and asserts the reader runs on the activation's slot.
- Spawning a second job on one permit is refused by the pool (`Permit::spawn` asserts one job per permit, and dispatch bounds busy threads by active permits), so activation and reading are one job: `NativeCaptureSession::prepare` splits the owner half from the reader, a rendezvous channel hands the owner half back, and `attach` builds the session on the activation's permit.
- `ReaperClient` no longer holds a pool or admits; `client_with_receiver` takes only the queue capacity, and tests that need permits admit from a local `Pool`.
