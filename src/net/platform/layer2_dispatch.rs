// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native Layer 2 transmission capability dispatch.

#![forbid(unsafe_code)]

use super::super::Error as LiveIoError;

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
pub(in crate::net) fn system_send_layer2(
    frame: super::super::transmit::Layer2Frame<'_>,
) -> Result<super::super::transmit::IoSendReport, LiveIoError> {
    super::validate_current_interface_identity(&frame.route().plan.route.interface)?;
    super::pcap_backend::send_layer2(frame)
}

#[cfg(all(feature = "native-layer2", windows))]
pub(in crate::net) fn system_send_layer2(
    frame: super::super::transmit::Layer2Frame<'_>,
) -> Result<super::super::transmit::IoSendReport, LiveIoError> {
    super::validate_current_interface_identity(&frame.route().plan.route.interface)?;
    super::npcap::send_layer2(frame)
}

#[cfg(any(
    not(feature = "native-layer2"),
    all(
        feature = "native-layer2",
        not(any(target_os = "linux", target_os = "macos", windows))
    )
))]
pub(in crate::net) fn system_send_layer2(
    _frame: super::super::transmit::Layer2Frame<'_>,
) -> Result<super::super::transmit::IoSendReport, LiveIoError> {
    Err(super::unsupported_live_io(
        "enable the native-layer2 feature on a supported target for Layer 2 injection",
    ))
}
