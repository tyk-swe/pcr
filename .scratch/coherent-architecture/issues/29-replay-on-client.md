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

**Status:** resolved

- [x] Replay has no public authorizer or transmitter type.
- [x] Replay error classification and the CLI replay tests pass unchanged.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Final-wire authorization is the internal `replay::admission::FinalWire`
  trait; resolve-and-authorize was split in 25 (decision round 2 a).
- The frame authorizer is the internal `FrameAdmission`, built over
  `client.admission()` (limits) and the client's registry. It lives in
  `replay/admission.rs`, a replay-specific concept beside the fixed roles
  (`request`, `plan`, `engine`, `executor`, `evidence`, `report`, `error`).
- The request keeps a source-independent `replay::Options` (plus
  `allow_permissive_live`) so the CLI still validates it before opening the
  capture; `Request { source, selector, options }`.
- The CLI JSON path converts each frame in its own sink, not
  `replay::Collector`, so an unrepresentable frame still stops the replay at
  that frame. The capture path's sink owns the capture writer; the command
  keeps the compressor and finishes it after the replay.
- Replay now registers the `client_progress` runtime in the `resources`
  report (it had no runtime before); recorded under Changed.
- CLI replay unit tests use a client over fake interface/route/transmit
  providers; the policy-denial fixture is now `policy.packet_limit` instead
  of a scripted `policy.fixture_replay`.
