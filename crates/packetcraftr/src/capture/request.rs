// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::time::Duration;

use packetcraftr_core::frame::Frame;
use packetcraftr_netio::capture::GroupRequest;

use crate::BoundaryError;

/// The boxed frame selector a request carries.
type SelectFrame = Box<dyn FnMut(u64, &Frame) -> Result<bool, BoundaryError> + Send>;

/// One capture: the interfaces and native settings every source arms with,
/// how long frames are delivered, and which of them are published.
pub struct Request {
    /// The interfaces to capture from, with the queue limits, filter, and
    /// native settings every source shares.
    pub group: GroupRequest,
    /// How long frames are delivered, measured on the client's clock from the
    /// start of the capture. Arming and readiness count against it. A zero
    /// window still arms every source, reports their metadata, and stops
    /// without delivering a frame.
    pub window: Duration,
    /// Chooses the admitted frames to publish; `None` publishes all of them.
    /// Set with [`with_selector`](Self::with_selector).
    pub(crate) select: Option<SelectFrame>,
}

impl Request {
    /// A capture of `group` for `window` that publishes every admitted frame.
    #[must_use]
    pub fn new(group: GroupRequest, window: Duration) -> Self {
        Self {
            group,
            window,
            select: None,
        }
    }

    /// Publishes only the admitted frames `select` keeps. `select` receives
    /// each frame's one-based position among every frame the capture
    /// delivered; it runs on the capture's own thread, before the frame is
    /// published, and a failure stops the capture.
    #[must_use]
    pub fn with_selector(
        mut self,
        select: impl FnMut(u64, &Frame) -> Result<bool, BoundaryError> + Send + 'static,
    ) -> Self {
        self.select = Some(Box::new(select));
        self
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("group", &self.group)
            .field("window", &self.window)
            .field("select", &self.select.as_ref().map(|_| "Selector"))
            .finish()
    }
}
