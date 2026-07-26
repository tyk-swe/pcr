// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native live-capture provider.

#![forbid(unsafe_code)]

use packetcraftr_net::Error;
use packetcraftr_net::capture::{Limits, Provider as CaptureProvider, SystemSession};
use packetcraftr_net::route::PlannedRoute;

pub use packetcraftr_net::capture::SystemSession as Session;

/// Native capture provider selected for the current target and the explicit
/// `native-layer2` feature.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl CaptureProvider for SystemProvider {
    type Capture = SystemSession;

    fn arm_capture(&self, route: &PlannedRoute, limits: Limits) -> Result<Self::Capture, Error> {
        crate::platform::system_capture(route, limits).map(SystemSession::new)
    }
}
