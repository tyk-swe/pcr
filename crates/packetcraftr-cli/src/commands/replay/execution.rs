// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;

use packetcraftr::{analysis::pcap::Reader, core::frame::Frame};

use crate::errors::CliError;
use crate::filtering::FrameSelector;

use super::classified_error;

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

pub(super) fn run<F>(
    reader: &mut Reader<File>,
    options: &packetcraftr::replay::Options,
    selector: Option<&mut dyn packetcraftr::replay::Selector>,
    authorizer: &mut packetcraftr::replay::SystemAuthorizer,
    transmitter: &mut packetcraftr::replay::SystemTransmitter,
    clock: &mut packetcraftr::clock::SystemClock,
    sink: F,
) -> Result<packetcraftr::replay::Summary, CliError>
where
    F: FnMut(packetcraftr::replay::FrameEvidence) -> Result<(), packetcraftr::replay::Error>,
{
    packetcraftr::replay::run_with_selector(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        sink,
    )
    .map_err(classified_error)
}
