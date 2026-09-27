# 03: Neutral checks out of platform/

**What to build:**
- The IPv4/IPv6 header and route-consistency validation moves from `platform/transmit/raw_ip/preparation.rs` to a crate-private `transmit::raw_ip` (`cfg(native_layer3)`). The platform `raw_ip` keeps only the macOS byte-order rewrite, the Windows UDP restriction, and the socket submission.
- The capture-side identity check (`validate_current_interface_identity`) moves into `capture/system.rs`; `interface::identity_changed` is the shared `Error::Device` constructor; `platform/interface/identity.rs` keeps the libc check and the Windows enumeration fallback. `dispatch::current_interface` goes away.
- Retained exceptions are documented in `platform/route.rs` and `platform/common.rs`.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] Every file under `platform/` calls a native API, declares native modules, or is target-gated ABI knowledge.
- [ ] Preparation tests move with the code; fmt, clippy, and the workspace tests pass.
