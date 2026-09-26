# 19: One deadline and cancellation convention for providers

**What to build:** Every provider call that can block takes the same deadline and cancellation input. Today capture uses a `Cancellable` wrapper, `Group::arm` takes `Option<Cancellation>`, `tcp::start_connect` takes a `Cancellation`, and neighbor and materialize take `Option<Instant>`. Route lookup takes the caller's deadline, replacing the hard-coded backend timeouts (`netlink/worker.rs` 2s/3s, `af_route/query.rs` 2s, none in IP Helper). The convention uses core's `Deadline` type. Phase 2.

**Blocked by:** 18

**Status:** ready-for-agent

- [ ] No backend has its own route timeout constant.
- [ ] A fake-backend test shows route lookup failing with the duration classification when the caller's deadline passes.
- [ ] Native-isolated tests pass on the Linux launcher.
- [ ] `[Unreleased]` records the behavior change (route lookup honors the caller's deadline).
- [ ] fmt, clippy and the workspace tests pass.
