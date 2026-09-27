# 25: Client owns providers; send and exchange on the new model

**What to build:**
- The `Client` holds the policy, protocol registry, clock, runtime, and route, interface, transmit and capture providers. `PacketIo` is removed from netio, and the `Sender as PacketIo` alias goes away.
- The client has one internal admission path, which every workflow will use.
- `send` and `exchange` move onto the model:
  - They use the injected clock and core's `Deadline` instead of `Instant`.
  - They publish through the event-sink contract from ticket 24, replacing send's synchronous `FnMut(&SentFrame)` callback and `SetReport`.
  - Their modules take the fixed roles (`request`, `plan`, `engine`, `executor`, `evidence`, `report`, `error`); `send/model.rs` and `exchange/model.rs` dissolve.
- Update `scripts/check-external-consumer.py` and the crate docs to the client model.

Phase 3. See `CONTEXT.md` **Client**, **Workflow**, **Exchange**.

**Blocked by:** 24

**Status:** resolved

- [x] `client.send(request, sink)` and `client.exchange(request, sink)` are the entry points, with no second `Runtime` argument or field.
- [x] A test-support fake-provider test shows admission running before any route or neighbor call for both workflows.
- [x] The send, exchange and staged-preparation contract tests pass. The external consumer check passes.
- [x] `[Unreleased]` and the migration note describe the client model.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- The bundle is `Providers`/`ProviderSet` (with `SystemProviders` = `ProviderSet::system()`), held as `Arc<P>` (decision e). Admission is the crate-private `execution::Admission` (typed `authorize` for preparation; `Authorizer + ResolveTarget` for 26–30). `target::ResolveTarget` is split out of `Authorizer` here (round 2 a).
- No `client.executor(settings)`/`execution::Settings`: executors keep `probe::ExchangeExecutor::new(&client, send::Options, exchange::Collection)`, and the scan registry override uses a crate-private `Client::view_with_registry` instead of the removed `Routes`/`Io` newtypes.
- `Clock::sleep` also takes the operation `Deadline` so the system clock honors the client's cancellation; `Clock::cancellation`/`CancellableClock` stay until 31.
- Send has no operation deadline (as before); each publication waits at most `capture::MAX_TIMEOUT`. New library-only codes: `io.send_clock`, `internal.send_event_coherence`, `internal.unresolved_interface`. The client remembers the last resolved interface selector, so a command enumerates interfaces once.
- `scripts/check-external-consumer.py` needed no change; the consumer example it compiles moved to the client model. `Discard` is not added (no user yet). CLI runtime names are unchanged; `system::client` now takes the runtime name (decision c).
