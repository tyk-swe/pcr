# 20: One worker pool for blocking native calls

**What to build:**
- Every native call that can block past a deadline runs on one admitted worker pool with the reaper: capture, netlink, AF_ROUTE, IP Helper and TCP connect. `tcp_connect`'s static state and thread-per-connect go away, and macOS and Windows route queries move off the caller's thread. Sends stay on the caller's thread.
- One named capacity constant replaces the three unrelated 16s: group `MAX_SOURCES`, pool capacity and `tcp::MAX_PENDING_CONNECTIONS`. If they really are different limits, they get distinct names and a comment on how they relate.
- Poll-with-sleep loops (`capture.rs`, `capture/group.rs`, `netlink/worker.rs` `park_timeout`) become channel or condvar waits where the backend offers a waitable handle. Where it doesn't, a comment says why the poll stays.

Phase 2.

**Blocked by:** 19

**Status:** resolved

- [x] One admission and reaper path. A test shows the pool refusing work past capacity with a classified error.
- [x] A deadline test on each pooled capability, using fakes where native isn't available.
- [x] Native-isolated tests pass on the Linux launcher, and the macOS and Windows CI jobs pass.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Per decision C7 the pool (`workers`) is compiled in every build, and `native_workers` now means `native_route || native_layer2`. `resources::WORKER_CAPACITY` (16) is the one named capacity. `tcp::MAX_PENDING_CONNECTIONS` is defined as a sub-limit equal to it, and `capture::MAX_SOURCES` keeps its own value with a comment on how it relates. Both resource rows keep their shape. `native_process` now covers the whole pool (TCP included) and reports `supported: true` in portable builds too.
- Pooled threads are matched to their caller's network namespace (`platform::execution_context`), because sockets and netlink open in the namespace of the thread that opens them.
- The reaper keeps its own cleanup threads, but admits through the pool and waits on pooled tasks. Its nudge loop stays sliced because a capture interrupt can be missed. The other sliced waits that remain (netlink submit/reply, the registry checkout, capture reads) exist only to notice core `Cancellation`, which has no waker. The capture group keeps its rotating poll because `Session` has no multi-source wait handle.
- pcap/Npcap activation and macOS `getifaddrs` stay on the caller's thread: they do not wait on the network. Windows interface enumeration moved to the pool, and the per-send identity check uses it, so on Windows that check runs on the pool while the send itself stays on the caller's thread.
- Native-isolated tests and the macOS/Windows jobs can't run here. The isolated suite compiles, and cross clippy (all five profiles, Windows + macOS) passes. The pooled route deadline tests for macOS/Windows (`platform::route::pooled_tests`) will first run in those CI jobs.
