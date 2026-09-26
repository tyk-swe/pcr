# 20: One worker pool for blocking native calls

**What to build:**
- Every native call that can block past a deadline runs on one admitted worker pool with the reaper: capture, netlink, AF_ROUTE, IP Helper and TCP connect. `tcp_connect`'s static state and thread-per-connect go away, and macOS and Windows route queries move off the caller's thread. Sends stay on the caller's thread.
- One named capacity constant replaces the three unrelated 16s: group `MAX_SOURCES`, pool capacity and `tcp::MAX_PENDING_CONNECTIONS`. If they really are different limits, they get distinct names and a comment on how they relate.
- Poll-with-sleep loops (`capture.rs`, `capture/group.rs`, `netlink/worker.rs` `park_timeout`) become channel or condvar waits where the backend offers a waitable handle. Where it doesn't, a comment says why the poll stays.

Phase 2.

**Blocked by:** 19

**Status:** ready-for-agent

- [ ] One admission and reaper path. A test shows the pool refusing work past capacity with a classified error.
- [ ] A deadline test on each pooled capability, using fakes where native isn't available.
- [ ] Native-isolated tests pass on the Linux launcher, and the macOS and Windows CI jobs pass.
- [ ] fmt, clippy and the workspace tests pass.
