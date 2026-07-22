// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native Layer 3 transmission capability dispatch.

#![forbid(unsafe_code)]

use super::super::Error as LiveIoError;

#[cfg(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(in crate::net) fn system_send_layer3(
    frame: super::super::transmit::Layer3Frame<'_>,
) -> Result<super::super::transmit::IoSendReport, LiveIoError> {
    super::validate_current_interface_identity(&frame.route().plan.route.interface)?;
    super::raw_ip::send_layer3(frame)
}

#[cfg(not(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
)))]
pub(in crate::net) fn system_send_layer3(
    _frame: super::super::transmit::Layer3Frame<'_>,
) -> Result<super::super::transmit::IoSendReport, LiveIoError> {
    Err(super::unsupported_live_io(
        "enable the native-layer3 feature on Linux, macOS, or Windows for raw IP transmission",
    ))
}
