// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tuple composition for capture-before-send exchanges.

use super::Error;
use super::capture;
use super::transmit;

impl<S, C> transmit::Sender for (S, C)
where
    S: transmit::Sender,
    C: Send + Sync,
{
    fn send(&self, frame: transmit::Frame<'_>) -> Result<transmit::Report, Error> {
        self.0.send(frame)
    }
}

impl<S, C> capture::Provider for (S, C)
where
    S: Send + Sync,
    C: capture::Provider,
{
    type Capture = C::Capture;

    fn arm_capture(&self, request: &capture::Request) -> Result<Self::Capture, Error> {
        self.1.arm_capture(request)
    }
}
