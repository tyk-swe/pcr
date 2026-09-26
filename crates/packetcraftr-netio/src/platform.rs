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
mod execution_context;
#[cfg(native_send)]
mod interface_identity;
#[cfg(native_layer2)]
mod layer2;
#[cfg(native_layer3)]
mod layer3;
#[cfg(native_route)]
mod route;

#[cfg(not(native_layer2))]
pub(crate) use dispatch::unsupported;
#[cfg(native_send)]
pub(crate) use dispatch::verify_interface_identity;
#[cfg(native_layer2)]
pub(crate) use dispatch::{current_interface, open_capture, timestamp_types};
pub(crate) use dispatch::{interface_route, interfaces, route, send_layer2, send_layer3};
pub(crate) use execution_context::{ExecutionContext, current as execution_context};
