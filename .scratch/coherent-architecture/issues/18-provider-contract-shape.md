# 18: One provider contract shape

**What to build:**
- Every netio capability is `<capability>::Provider` with a `<capability>::SystemProvider`, and every provider trait has `Send + Sync` supertraits. The capabilities are route, interface, capture, transmit and tcp; tcp gains the bounds it lacks today.
- Transmit becomes one `transmit::Provider` that sends any frame. `transmit::SystemProvider` dispatches Layer 2 or Layer 3 to its backend and returns a classified capability error when that layer isn't compiled in.
- `Layer2Sender`, `Layer3Sender`, `SystemLayer2`, `SystemLayer3` and `ModeSender` are removed. `transmit::Frame` is renamed so it no longer collides with `core::frame::Frame`.
- `route::Provider` stops using `classify_error()` and returns an error that implements `Classified`.
- `PacketIo` stays until ticket 25.

Phase 2. See `CONTEXT.md` **Provider**, **System provider**.

**Blocked by:** 17

**Status:** ready-for-agent

- [ ] All providers share naming and bounds, and the test-support fakes implement the new traits.
- [ ] A test covers the transmit `SystemProvider` returning the capability error for a layer that isn't built. Run it under `--no-default-features` plus one layer feature.
- [ ] `[Unreleased]` and the migration note list the trait changes.
- [ ] fmt, clippy and the workspace tests pass.
