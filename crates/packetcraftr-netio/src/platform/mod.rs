// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private FFI and reviewed-unsafe-code boundary.
//!
//! The `native_*`, `pcap_backend`, `npcap_backend`, and `worker_reaper`
//! predicates come from the build script, which combines the enabled
//! features with the target the crate is compiled for.

#[cfg(all(native_route, target_os = "macos"))]
mod af_route;
#[cfg(native_layer2)]
mod capture_filter;
mod dispatch;
#[cfg(native_send)]
mod interface_identity;
#[cfg(native_route)]
mod interface_validation;
#[cfg(all(native_route, windows))]
mod iphelper;
#[cfg(native_layer2)]
mod live_capture;
#[cfg(all(native_route, target_os = "linux"))]
mod netlink;
#[cfg(npcap_backend)]
mod npcap;
#[cfg(pcap_backend)]
mod pcap_backend;
#[cfg(native_layer2)]
mod pcap_common;
#[cfg(native_layer3)]
mod raw_ip;
#[cfg(native_route)]
mod route_normalize;
#[cfg(worker_reaper)]
mod worker_reaper;

/// Wraps a native failure as the operating-system route diagnostic.
///
/// Linux and macOS phrased this identically in their own modules; Windows
/// keeps its own because it also renders the Win32 status code.
#[cfg(all(native_route, any(target_os = "linux", target_os = "macos")))]
fn os_error(
    operation: &'static str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> crate::route::SystemError {
    crate::route::SystemError::OperatingSystem {
        operation,
        message: "the operating system refused the request".to_owned(),
        source: Some(std::sync::Arc::new(error)),
    }
}

pub(crate) use dispatch::{
    system_capture, system_interface_route, system_interfaces, system_route, system_send_layer2,
    system_send_layer3,
};
