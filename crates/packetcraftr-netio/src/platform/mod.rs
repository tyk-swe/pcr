// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private FFI and reviewed-unsafe-code boundary.

mod capture_dispatch;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod capture_filter;
mod interface_dispatch;
#[cfg(all(
    any(feature = "native-layer2", feature = "native-layer3"),
    any(target_os = "linux", target_os = "macos", windows)
))]
mod interface_identity;
#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
mod interface_validation;
mod layer2_dispatch;
mod layer3_dispatch;
#[cfg(all(target_os = "linux", feature = "native-route"))]
mod linux;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod live_capture;
#[cfg(all(target_os = "macos", feature = "native-route"))]
mod macos;
#[cfg(all(feature = "native-layer2", windows))]
mod npcap;
#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
mod pcap_backend;
#[cfg(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod raw_ip;
mod route_dispatch;
#[cfg(all(windows, any(feature = "native-interfaces", feature = "native-route")))]
mod windows;
#[cfg(any(
    all(target_os = "linux", feature = "native-route"),
    all(
        feature = "native-layer2",
        any(target_os = "linux", target_os = "macos", windows)
    )
))]
mod worker_reaper;

pub(crate) use capture_dispatch::system_capture;
pub(crate) use interface_dispatch::system_interfaces;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) use interface_validation::validate_native_interface;
pub(crate) use layer2_dispatch::system_send_layer2;
pub(crate) use layer3_dispatch::system_send_layer3;
pub(crate) use route_dispatch::{system_interface_route, system_route};
