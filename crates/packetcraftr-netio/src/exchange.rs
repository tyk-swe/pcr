// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tuple composition for capture-before-send exchanges.

use super::Error;
use super::capture::{CaptureProvider, CaptureQueueLimits};
use super::route::PlannedRoute;
use super::transmit::{IoSendReport, PacketIo, TransmissionFrame};

impl<S, C> PacketIo for (S, C)
where
    S: PacketIo,
    C: Send + Sync,
{
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, Error> {
        self.0.send(frame)
    }
}

impl<S, C> CaptureProvider for (S, C)
where
    S: Send + Sync,
    C: CaptureProvider,
{
    type Capture = C::Capture;

    fn arm_capture(
        &self,
        route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, Error> {
        self.1.arm_capture(route, limits)
    }

    fn arm_capture_with_filter(
        &self,
        route: &PlannedRoute,
        limits: CaptureQueueLimits,
        filter: &str,
    ) -> Result<Self::Capture, Error> {
        self.1.arm_capture_with_filter(route, limits, filter)
    }
}
