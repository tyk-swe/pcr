# 31: packetcraftr public surface

**What to build:** With every workflow on the client, apply the facade rule to packetcraftr:
- The `Executor`, `Authorizer`, `Selector`-style seams that the client now owns are `pub(crate)`.
- No aliases remain.
- `BoundaryError` appears in public signatures only where a caller supplies a sink; it is referenced by its core path.
- `Execution`, `Transport`, `Limits` and `Stats` each name one kind of thing.
- `lib.rs` docs describe the client model and the fixed roles.

Phase 3.

**Blocked by:** 26, 27, 28, 29, 30

**Status:** ready-for-agent

- [ ] Each public item has one path, and no public name means two different things.
- [ ] `scripts/check-external-consumer.py` passes.
- [ ] `[Unreleased]` and the migration note are complete for phase 3.
- [ ] fmt, clippy and the workspace tests pass.
