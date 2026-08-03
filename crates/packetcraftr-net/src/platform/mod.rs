// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Crate-private native adapter boundary.
//!
//! This directory is the only location in the crate permitted to contain FFI
//! or narrowly reviewed unsafe code. Public traits and values live in `net`.

mod capture_dispatch;
mod interface_dispatch;
mod interface_identity;
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
    feature = "native-interfaces",
    not(windows),
    not(all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ))
))]
mod pnet_enumeration;
#[cfg(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
))]
mod raw_ip;
mod route_dispatch;
#[cfg(test)]
mod tests;
mod unsupported;
#[cfg(all(windows, any(feature = "native-interfaces", feature = "native-route")))]
mod windows;

#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos")
))]
pub(crate) use super::route::find_interface;
#[cfg(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) use super::route::{
    NativeRouteSnapshot, finish_route, interface_decision, validate_preferred_source_family,
};
pub(crate) use capture_dispatch::{system_capture, system_capture_with_filter};
pub(crate) use interface_dispatch::system_interfaces;
#[cfg(any(
    test,
    all(
        any(feature = "native-layer2", feature = "native-layer3"),
        any(target_os = "linux", target_os = "macos", windows)
    )
))]
#[allow(unused_imports)]
pub(crate) use interface_identity::interface_identity_matches;
#[cfg(all(
    any(feature = "native-layer2", feature = "native-layer3"),
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) use interface_identity::validate_current_interface_identity;
#[cfg(any(
    all(
        feature = "native-route",
        any(target_os = "linux", target_os = "macos")
    ),
    all(any(feature = "native-interfaces", feature = "native-route"), windows)
))]
pub(crate) use interface_validation::{
    interface_error, validate_native_interface, validate_native_interfaces,
};
pub(crate) use layer2_dispatch::system_send_layer2;
pub(crate) use layer3_dispatch::system_send_layer3;
pub(crate) use route_dispatch::{system_interface_route, system_route};
#[cfg(any(
    not(all(
        feature = "native-layer2",
        any(target_os = "linux", target_os = "macos", windows)
    )),
    not(all(
        feature = "native-layer3",
        any(target_os = "linux", target_os = "macos", windows)
    )),
    all(
        feature = "native-route",
        not(any(target_os = "linux", target_os = "macos", windows)),
        not(feature = "native-interfaces")
    )
))]
pub(crate) use unsupported::unsupported_live_io;
#[cfg(not(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
)))]
pub(crate) use unsupported::unsupported_native_route;
