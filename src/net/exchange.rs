//! Composition contracts for capture-before-send exchanges.

use super::Error;
use super::capture::{CaptureProvider, CaptureQueueLimits};
use super::route::PlannedRoute;
use super::transmit::{IoSendReport, PacketIo, TransmissionFrame};

/// A provider that supports both transmission and capture.
pub trait Io: PacketIo + CaptureProvider {}

impl<T> Io for T where T: PacketIo + CaptureProvider {}

pub(crate) use Io as ExchangeIo;

/// Composes separately owned transmission and capture providers.
#[derive(Clone, Copy, Debug)]
pub struct Composite<S, C> {
    sender: S,
    capture: C,
}

impl<S, C> Composite<S, C> {
    pub fn new(sender: S, capture: C) -> Self {
        Self { sender, capture }
    }

    pub fn sender(&self) -> &S {
        &self.sender
    }

    pub fn capture(&self) -> &C {
        &self.capture
    }

    pub fn into_parts(self) -> (S, C) {
        (self.sender, self.capture)
    }
}

impl<S, C> PacketIo for Composite<S, C>
where
    S: PacketIo,
    C: Send + Sync,
{
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, Error> {
        self.sender.send(frame)
    }
}

impl<S, C> CaptureProvider for Composite<S, C>
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
        self.capture.arm_capture(route, limits)
    }
}
