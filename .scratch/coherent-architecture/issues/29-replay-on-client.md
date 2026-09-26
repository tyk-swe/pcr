# 29: Replay on the client

**What to build:**
- Replay becomes `client.replay(request, sink)`. `SystemTransmitter` and `SystemAuthorizer` become internal: the client's transmit provider replaces the hard-wired native senders, and the shared admission path replaces the separate authorizer, including its `Policy`-by-value plus bare `bool` constructor.
- Final-wire authorization and resolve-and-authorize become separate capability traits instead of default methods that fail.
- The `Option<&mut dyn Selector>` argument becomes a generic or a request field, consistent with the other workflows.
- Replay publishes `Event` values through the sink (replacing `FnMut(FrameEvidence)`).
- `Error::Output { message: String }` keeps its source.
- The private `Progress` that shadows the public module is renamed.
- The module takes the fixed roles (`model.rs`, `transmitter.rs` and `authorizer.rs` dissolve).

Phase 3.

**Blocked by:** 25

**Status:** ready-for-agent

- [ ] Replay has no public authorizer or transmitter type.
- [ ] Replay error classification and the CLI replay tests pass unchanged.
- [ ] fmt, clippy and the workspace tests pass.
