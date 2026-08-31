// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native Layer 3 transmission capability dispatch.

use crate::{
    Error,
    transmit::{self, Layer3Frame},
};

#[cfg(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
))]
use super::raw_ip as backend;

#[cfg(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
))]
pub(crate) fn system_send_layer3(frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    super::interface_identity::verify_interface_identity(&frame.route().plan.decision.interface)?;
    backend::send_layer3(frame)
}

#[cfg(not(all(
    feature = "native-layer3",
    any(target_os = "linux", target_os = "macos", windows)
)))]
pub(crate) fn system_send_layer3(_frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    Err(Error::Unsupported {
        message:
            "enable the native-layer3 feature on Linux, macOS, or Windows for raw IP transmission"
                .to_owned(),
        source: None,
    })
}
