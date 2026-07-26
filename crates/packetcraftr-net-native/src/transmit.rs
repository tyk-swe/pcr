// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native Layer 2 and raw Layer 3 transmission providers.

#![forbid(unsafe_code)]

use packetcraftr_net::Error;
use packetcraftr_net::transmit::{Layer2Frame, Layer2Sender, Layer3Frame, Layer3Sender, Report};

/// Native Layer 2 injection provider selected for the current target. Builds
/// without `native-layer2` return an actionable capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLayer2;

impl Layer2Sender for SystemLayer2 {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error> {
        crate::platform::system_send_layer2(frame)
    }
}

/// Native raw-IP provider selected for the current target. Builds without
/// `native-layer3` return an actionable capability error.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLayer3;

impl Layer3Sender for SystemLayer3 {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error> {
        crate::platform::system_send_layer3(frame)
    }
}
