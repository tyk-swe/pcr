// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Unsupported live I/O and route error constructors.

#![forbid(unsafe_code)]

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
use crate::Error as LiveIoError;

#[cfg(not(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
)))]
use crate::route::NativeRouteError;

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
pub(crate) fn unsupported_live_io(message: &'static str) -> LiveIoError {
    LiveIoError::Unsupported {
        message: message.to_owned(),
    }
}

#[cfg(not(all(
    feature = "native-route",
    any(target_os = "linux", target_os = "macos", windows)
)))]
pub(crate) fn unsupported_native_route(message: &'static str) -> NativeRouteError {
    NativeRouteError::Unsupported {
        message: message.to_owned(),
    }
}
