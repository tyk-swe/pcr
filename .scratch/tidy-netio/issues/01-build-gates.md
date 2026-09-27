# 01: Build gates and feature lists

**What to build:**
- `build.rs` drops `native_workers` (always equal to `native_route`); its three `allow(dead_code)` uses gate on `native_route`. The `platform.rs` cfg list names every emitted predicate, including `packetcraftr_test_netns`.
- `platform.rs` gates `interface` on `native_route`; `platform/interface.rs` drops the redundant `all(native_route, …)` wrappers.
- One Windows spelling inside `platform/`: `target_os = "windows"`.
- `Cargo.toml` features stop repeating `dep:libc`/`dep:socket2` that `native-route` already enables.
- `platform/common/npcap/abi.rs` keeps `#![allow(unsafe_code)]` only if clippy needs it.

**Status:** ready-for-agent

- [ ] Every `cargo::rustc-cfg` in `build.rs` is used outside `build.rs`.
- [ ] fmt, the five clippy profiles, and the workspace tests pass.
