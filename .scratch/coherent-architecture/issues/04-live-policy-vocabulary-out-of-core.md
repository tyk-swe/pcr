# 04: Move live-policy vocabulary out of core

**What to build:** Per ADR 0002, core keeps runtime-neutral packet knowledge (matchers, packet semantics) and gives up vocabulary that only makes sense under live policy. The following move to packetcraftr:
- `build::Options::requires_live_opt_in`;
- `Coordinate::ProbeSequence` and `Coordinate::Attempt`;
- the `Deadline` helpers that no core code calls (`remaining_before`, `into_boundary_error`, `for_wait`, `bounded_timeout`, `POLL_INTERVAL`);
- the `deadline_error_conversions!` macro.

Packet semantics errors are reworded to describe the packet (for example "destination cannot be determined because …") instead of a transmission denial; packetcraftr maps them to its policy denial. Phase 1.

**Blocked by:** 03

**Status:** resolved

- [x] Core contains no items whose only meaning is live policy; the matchers and `packet::semantics` stay.
- [x] Denial classification codes published by live commands are unchanged.
- [x] `[Unreleased]` and the migration note list the moved paths.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Per the orchestrator decisions, helpers moved to the lowest crate that uses
  them: `remaining_before` and `POLL_INTERVAL` to
  `packetcraftr_netio::deadline` (netio uses both), `bounded_timeout` and
  `for_wait` to the `packetcraftr::deadline::DeadlineExt` trait (core
  `Deadline` gained `limit()` and `cancellation()`).
  `Cancelled::into_boundary_error` was inlined at its one caller.
  `deadline_error_conversions!` is crate-private in both core and packetcraftr.
- `Coordinate::ProbeSequence`/`Attempt` stay in core (decision: classification
  vocabulary whose serialized keys are frozen in the envelope).
- `requires_live_opt_in` was a `BuiltPacket` field, not a `build::Options` one.
  Core now exposes `BuiltPacket::mode`, `contains_malformed()` and
  `contains_network_trailer()`; the predicate is
  `packetcraftr::policy::requires_live_opt_in`.
- `semantics::live_destinations` keeps its name; only its docs changed.

