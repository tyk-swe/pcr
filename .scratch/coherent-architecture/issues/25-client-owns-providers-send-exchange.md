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

**Status:** ready-for-agent

- [ ] `client.send(request, sink)` and `client.exchange(request, sink)` are the entry points, with no second `Runtime` argument or field.
- [ ] A test-support fake-provider test shows admission running before any route or neighbor call for both workflows.
- [ ] The send, exchange and staged-preparation contract tests pass. The external consumer check passes.
- [ ] `[Unreleased]` and the migration note describe the client model.
- [ ] fmt, clippy and the workspace tests pass.
