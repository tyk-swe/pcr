// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::frame::Frame;

use crate::errors::CliError;
use crate::filtering::FrameSelector;

/// Bridges the CLI display filter to replay selection. Rejected frames skip
/// authorization, delay, and transmission; undecodable frames fail replay.
pub(super) struct FilterSelector<'a> {
    pub(super) selector: &'a FrameSelector,
}

impl packetcraftr::replay::Selector for FilterSelector<'_> {
    fn select(&mut self, number: u64, frame: &Frame) -> Result<bool, packetcraftr::BoundaryError> {
        self.selector
            .keep(number, frame)
            .map_err(CliError::into_boundary_error)
    }
}
