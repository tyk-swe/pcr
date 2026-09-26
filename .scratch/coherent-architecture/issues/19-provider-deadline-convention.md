# 19: One deadline and cancellation convention for providers

**What to build:** Every provider call that can block takes the same deadline and cancellation input. Today capture uses a `Cancellable` wrapper, `Group::arm` takes `Option<Cancellation>`, `tcp::start_connect` takes a `Cancellation`, and neighbor and materialize take `Option<Instant>`. Route lookup takes the caller's deadline, replacing the hard-coded backend timeouts (`netlink/worker.rs` 2s/3s, `af_route/query.rs` 2s, none in IP Helper). The convention uses core's `Deadline` type. Phase 2.

**Blocked by:** 18

**Status:** resolved

- [x] No backend has its own route timeout constant.
- [x] A fake-backend test shows route lookup failing with the duration classification when the caller's deadline passes.
- [x] Native-isolated tests pass on the Linux launcher.
- [x] `[Unreleased]` records the behavior change (route lookup honors the caller's deadline).
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Convention (C6): providers take `&packetcraftr_core::budget::Deadline`; its cancellation is the only cancellation input. Stated in `packetcraftr_netio::deadline` with `remaining`/`expires_at`/`detach` helpers.
- Beyond the listed calls, `interface::Provider::interfaces` and `capture::Provider::timestamp_types` also take the deadline, because they enumerate over netlink, which lost its own timeout. `replay::Transmitter::plan_frame` and `Client::plan` take the deadline their lookups receive.
- A capture read is the one call whose expiry is not a failure: a spent deadline takes only what is queued and returns `Ok(None)`. Capture readiness keeps `io.capture_readiness`, and a remainder above `capture::MAX_TIMEOUT` keeps `cli.capture_timeout`; only route/interface/arming/connect expiry publishes `io.deadline_exceeded`.
- Transmit keeps no deadline (spec: sends stay on the caller's thread). IP Helper calls are synchronous, so Windows checks the deadline between them; ticket 20 moves them onto the pool.
- The fake-backend tests are `packetcraftr/tests/route_contracts.rs::route_lookup_fails_with_the_deadline_classification_when_the_callers_deadline_passes` (fake provider through the public planner) and the netlink worker unit test with a stalled operation. Native-isolated tests compile here; the launcher run is CI-only (as C2).
- Callers with no operation deadline use `packetcraftr::deadline::PASSIVE_LOOKUP_TIMEOUT` (3 s, the old netlink response bound) for passive lookups; the CLI nests it inside the invocation deadline.
