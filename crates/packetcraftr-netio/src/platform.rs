// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private FFI and reviewed-unsafe-code boundary.
//!
//! Only code that calls a native API lives here, grouped by capability and
//! then by backend: `route` (route lookup and interface enumeration),
//! `layer2` (capture and Layer 2 injection), `layer3` (raw IP transmission),
//! and the per-send `interface_identity` check. `dispatch` selects the backend
//! the build script enabled for this target.
//!
//! The `native_*`, `pcap_backend`, `npcap_backend`, and `native_workers`
//! predicates come from the build script, which combines the enabled
//! features with the target the crate is compiled for.

mod dispatch;
#[cfg(native_send)]
mod interface_identity;
#[cfg(native_layer2)]
mod layer2;
#[cfg(native_layer3)]
mod layer3;
#[cfg(native_route)]
mod route;

pub(crate) use dispatch::{
    capture_timestamp_types, system_capture, system_interface_route, system_interfaces,
    system_route, system_send_layer2, system_send_layer3,
};
