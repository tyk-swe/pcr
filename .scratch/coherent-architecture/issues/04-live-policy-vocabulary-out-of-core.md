# 04: Move live-policy vocabulary out of core

**What to build:** Per ADR 0002, core keeps runtime-neutral packet knowledge (matchers, packet semantics) and gives up vocabulary that only makes sense under live policy. The following move to packetcraftr:
- `build::Options::requires_live_opt_in`;
- `Coordinate::ProbeSequence` and `Coordinate::Attempt`;
- the `Deadline` helpers that no core code calls (`remaining_before`, `into_boundary_error`, `for_wait`, `bounded_timeout`, `POLL_INTERVAL`);
- the `deadline_error_conversions!` macro.

Packet semantics errors are reworded to describe the packet (for example "destination cannot be determined because …") instead of a transmission denial; packetcraftr maps them to its policy denial. Phase 1.

**Blocked by:** 03

**Status:** ready-for-agent

- [ ] Core contains no items whose only meaning is live policy; the matchers and `packet::semantics` stay.
- [ ] Denial classification codes published by live commands are unchanged.
- [ ] `[Unreleased]` and the migration note list the moved paths.
- [ ] fmt, clippy and the workspace tests pass.
