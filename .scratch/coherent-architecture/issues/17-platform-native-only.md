# 17: platform/ holds only native code

**What to build:**
- `packetcraftr-netio/src/platform/` keeps only code that calls native APIs, organized as capability → backend.
- Platform-neutral code moves to its capability module: `route_normalize.rs` (which says "no FFI lives here"), `interface_validation.rs`, `capture_filter.rs`, `live_capture/{queue,time}.rs`, `workers.rs`, `worker_reaper.rs` and `tcp_connect.rs`.
- `dispatch.rs` only selects backends. Capture limit and filter validation, the interface identity check and the BPF netmask computation move to their capability.
- Interface enumeration gets its own error type instead of returning `route::SystemError`.
- Backend visibility is `pub(in crate::platform)` consistently.
- `AGENTS.md`'s platform rule is updated if its wording changes.

Phase 2.

**Blocked by:** 15

**Status:** resolved

- [x] Every file under `platform/` contains a native call, or is the backend module declaring its native files.
- [x] No `target_os` cfg appears outside `platform/`, and none appears in platform-neutral code.
- [x] The capability cfgs emitted by `build.rs` are unchanged, or updated together with `AGENTS.md`.
- [x] fmt, clippy and the workspace tests pass on Linux. The macOS and Windows CI jobs pass.

## Comments

- Layout: `platform/{route/{netlink,af_route,iphelper}, layer2/{pcap_backend,npcap,pcap_common}, layer3/raw_ip, interface_identity, dispatch}`. Neutral code moved to `route::normalize`, `interface::validation`, `capture::{filter, live, system}`, `tcp::connect`, and a crate-private `workers` (+ `workers::reaper`).
- C5: `layer2/pcap_common.rs` (libpcap ABI constants and status mapping), `npcap/error.rs`, `raw_ip/preparation.rs` and `af_route/parser.rs` stay as backend code. `platform/route.rs` declares the route backends and keeps the three helpers only some of them share (`os_error`, `find_interface`, `constrain_by_preferred_source`), because only a target gate says which backends use them.
- The per-send identity check and its enumeration fallback call native APIs and stay in `platform/interface_identity.rs`; the capture and transmit system providers now invoke them. `dispatch` keeps the fail-closed stubs for entry points with portable signatures; the capture stubs live in `capture::system`, whose native path needs capture-only types.
- Interface errors: `interface::Provider::interfaces` returns the new `interface::Error`. Route lookup and enumeration share native plumbing inside each backend, so the backend's `interfaces()` entry wraps that `route::SystemError` as the `Discovery` source.
- The preferred-source family check moved into `route::SystemProvider` and now also runs in portable builds (changelog "Changed").
- macOS and Windows: checked with cross `cargo clippy --all-targets -D warnings` (aarch64-apple-darwin, x86_64-pc-windows-msvc) under all five CI profiles. Their tests did not run here; CI is authoritative.
