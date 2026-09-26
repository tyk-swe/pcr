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

**Status:** ready-for-agent

- [ ] Every file under `platform/` contains a native call, or is the backend module declaring its native files.
- [ ] No `target_os` cfg appears outside `platform/`, and none appears in platform-neutral code.
- [ ] The capability cfgs emitted by `build.rs` are unchanged, or updated together with `AGENTS.md`.
- [ ] fmt, clippy and the workspace tests pass on Linux. The macOS and Windows CI jobs pass.
