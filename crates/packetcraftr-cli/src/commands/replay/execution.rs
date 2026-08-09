// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;

use packetcraftr::{analysis::pcap::Reader, live as workflow, packet::frame::Frame};

use crate::errors::CliError;
use crate::filtering::FrameSelector;

use super::replay_cli_error;

/// Bridges the CLI display filter to replay selection. Rejected frames skip
/// authorization, delay, and transmission; undecodable frames fail replay.
pub(super) struct DisplayFilterSelector<'a> {
    pub(super) selector: &'a FrameSelector,
}

impl workflow::replay::Selector for DisplayFilterSelector<'_> {
    fn select(&mut self, number: u64, frame: &Frame) -> Result<bool, workflow::BoundaryError> {
        self.selector
            .keep(number, frame)
            .map_err(CliError::into_boundary_error)
    }
}

pub(super) fn execute_replay<F>(
    reader: &mut Reader<File>,
    options: &workflow::replay::Options,
    selector: Option<&mut dyn workflow::replay::Selector>,
    authorizer: &mut workflow::replay::SystemAuthorizer,
    transmitter: &mut workflow::replay::SystemTransmitter,
    clock: &mut workflow::clock::SystemClock,
    sink: F,
) -> Result<workflow::replay::Summary, CliError>
where
    F: FnMut(workflow::replay::FrameEvidence) -> Result<(), workflow::replay::Error>,
{
    workflow::replay::run_with_selector(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        sink,
    )
    .map_err(replay_cli_error)
}
