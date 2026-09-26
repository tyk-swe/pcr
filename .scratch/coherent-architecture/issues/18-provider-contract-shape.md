# 18: One provider contract shape

**What to build:**
- Every netio capability is `<capability>::Provider` with a `<capability>::SystemProvider`, and every provider trait has `Send + Sync` supertraits. The capabilities are route, interface, capture, transmit and tcp; tcp gains the bounds it lacks today.
- Transmit becomes one `transmit::Provider` that sends any frame. `transmit::SystemProvider` dispatches Layer 2 or Layer 3 to its backend and returns a classified capability error when that layer isn't compiled in.
- `Layer2Sender`, `Layer3Sender`, `SystemLayer2`, `SystemLayer3` and `ModeSender` are removed. `transmit::Frame` is renamed so it no longer collides with `core::frame::Frame`.
- `route::Provider` stops using `classify_error()` and returns an error that implements `Classified`.
- `PacketIo` stays until ticket 25.

Phase 2. See `CONTEXT.md` **Provider**, **System provider**.

**Blocked by:** 17

**Status:** resolved

- [x] All providers share naming and bounds, and the test-support fakes implement the new traits.
- [x] A test covers the transmit `SystemProvider` returning the capability error for a layer that isn't built. Run it under `--no-default-features` plus one layer feature.
- [x] `[Unreleased]` and the migration note list the trait changes.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- `transmit::Frame` is now `transmit::Outbound`; `Layer2Frame`/`Layer3Frame` keep their names.
- C10: core implements `Classified` for `Infallible`; the `io::Error` route fake became `Infallible`, and the planner/cache fixtures implement `Classified` themselves.
- `tcp::Stream` also gained `Send`, like `capture::Session`, so `P::Stream: Send` bounds dropped to `'static`.
- The capability test is `packetcraftr-netio/tests/transmit_contracts.rs`, compiled only when a layer is missing. It passes under `--no-default-features` plus `native-layer2` or `native-layer3`, and under plain `--no-default-features`.
- The `ModeSender` dispatch test became an `Outbound::try_new` layer-selection test, since fakes can no longer be put behind the system dispatch.
