# 03: Neutral checks out of platform/

**What to build:**
- The IPv4/IPv6 header and route-consistency validation moves from `platform/transmit/raw_ip/preparation.rs` to a crate-private `transmit::raw_ip` (`cfg(native_layer3)`). The platform `raw_ip` keeps only the macOS byte-order rewrite, the Windows UDP restriction, and the socket submission.
- The capture-side identity check (`validate_current_interface_identity`) moves into `capture/system.rs`; `interface::identity_changed` is the shared `Error::Device` constructor; `platform/interface/identity.rs` keeps the libc check and the Windows enumeration fallback. `dispatch::current_interface` goes away.
- Retained exceptions are documented in `platform/route.rs` and `platform/common.rs`.

**Blocked by:** 02

**Status:** resolved

- [x] Every file under `platform/` calls a native API, declares native modules, or is target-gated ABI knowledge.
- [x] Preparation tests move with the code; fmt, clippy, and the workspace tests pass.

## Comments

- `transmit::raw_ip::validate(frame, target_restrictions)` takes the target's own refusal as a closure, so the Windows raw-UDP rule stays in `platform/transmit/raw_ip/preparation.rs` beside the macOS byte-order rewrite while the neutral checks compile everywhere Layer 3 does.
- `interface::current` carries `cfg_attr(not(native_layer2), allow(dead_code))`: Linux and macOS sends verify by name lookup, so a Layer-3-only build there has no caller, while Windows Layer-3-only builds still enumerate through it.
