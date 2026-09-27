# 02: Platform visibility and docs

**What to build:**
- Backend items shared across files are `pub(in crate::platform)`; items used only in their own file are private (`route/*/query.rs`, `capture/libpcap/bpf.rs`, `transmit/raw_ip/*.rs`, `interface/netlink.rs`, `interface/iphelper/adapter.rs`).
- `platform/common.rs` states the real rule for what it holds; `platform.rs` and `platform/interface.rs` say the macOS interface backend uses `getifaddrs(3)`.
- `common/netlink.rs` reuses `execution_context::current` for the namespace identity.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] No `pub(super)` remains under `platform/`.
- [ ] fmt, clippy, and the workspace tests pass.
