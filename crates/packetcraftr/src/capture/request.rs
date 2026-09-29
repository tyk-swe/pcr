// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::time::Duration;

use packetcraftr_core::frame::Frame;
use packetcraftr_netio::capture::GroupRequest;

use packetcraftr_core::error::BoundaryError;

pub(super) type SelectFrame = Box<dyn FnMut(u64, &Frame) -> Result<bool, BoundaryError> + Send>;

pub struct Request {
    pub group: GroupRequest,
    /// Arming and readiness count against it.
    pub window: Duration,
    pub(crate) select: Option<SelectFrame>,
}

impl Request {
    #[must_use]
    pub fn new(group: GroupRequest, window: Duration) -> Self {
        Self {
            group,
            window,
            select: None,
        }
    }

    /// `select` receives each frame's one-based position among every frame the capture delivered.
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
