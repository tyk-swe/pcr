// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private FFI and reviewed-unsafe-code boundary.
//!
//! Only code that calls a native API lives here, organized as capability →
//! backend:
//!
//! - `route`: route lookup (`netlink` on Linux, `af_route` on macOS,
//!   `iphelper` on Windows).
//! - `interface`: interface enumeration with the same three backends, and
//!   `identity`, the per-send check that an interface kept its name and index.
//! - `capture`: live capture (`libpcap` on Linux and macOS, the runtime-loaded
//!   `npcap` on Windows).
//! - `transmit`: Layer 2 injection (`libpcap`, `npcap`) and raw IP
//!   transmission (`raw_ip`).
//!
//! TCP connect uses only portable sockets, so it has no backend here.
//! `common` holds the native plumbing more than one capability's backend
//! shares (the netlink connection worker, Npcap's loader and handles, the
//! pcap API rules), and `execution_context` names the per-thread network
//! context the worker pool matches. `dispatch` selects the backend the build
//! script enabled for this target.
//!
//! The `native_*`, `pcap_backend`, `npcap_backend`, and `native_workers`
//! predicates come from the build script, which combines the enabled
//! features with the target the crate is compiled for.

#[cfg(native_layer2)]
mod capture;
mod common;
mod dispatch;
mod execution_context;
#[cfg(any(native_route, native_send))]
mod interface;
#[cfg(native_route)]
mod route;
#[cfg(native_send)]
mod transmit;

#[cfg(not(native_layer2))]
pub(crate) use dispatch::unsupported;
#[cfg(native_send)]
pub(crate) use dispatch::verify_interface_identity;
#[cfg(native_layer2)]
pub(crate) use dispatch::{current_interface, open_capture, timestamp_types};
pub(crate) use dispatch::{interface_route, interfaces, route, send_layer2, send_layer3};
pub(crate) use execution_context::{ExecutionContext, current as execution_context};
