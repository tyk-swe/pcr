// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native Layer 2 transmission capability dispatch.

#![forbid(unsafe_code)]

use crate::{
    Error as LiveIoError,
    transmit::{IoSendReport, Layer2Frame},
};

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos")
))]
use super::pcap_backend as layer2_backend;

#[cfg(all(feature = "native-layer2", windows))]
use super::npcap as layer2_backend;

#[cfg(all(
    feature = "native-layer2",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) fn system_send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    super::interface_identity::validate_current_interface_identity(
        &frame.route().plan.decision.interface,
    )?;
    layer2_backend::send_layer2(frame)
}

#[cfg(any(
    not(feature = "native-layer2"),
    all(
        feature = "native-layer2",
        not(any(target_os = "linux", target_os = "macos", windows))
    )
))]
pub(crate) fn system_send_layer2(_frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    Err(LiveIoError::Unsupported {
        message: "enable the native-layer2 feature on a supported target for Layer 2 injection"
            .to_owned(),
    })
}
