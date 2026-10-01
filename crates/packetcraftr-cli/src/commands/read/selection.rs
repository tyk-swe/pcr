// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core as core;
use packetcraftr_core::capture_file as capture;
use packetcraftr_core::filter::FrameDecoder;
use packetcraftr_core::registry::Registry;

use crate::command_options::FrameSelection;
use crate::errors::CliError;
use crate::filtering;

pub(super) struct Decoding {
    pub(super) frames: FrameDecoder,
    pub(super) publish_layers: bool,
}

pub(super) fn prepare_decoding(
    filter: Option<&str>,
    dissect: bool,
    registry: &Arc<Registry>,
    max_frame_bytes: usize,
) -> Result<Option<Decoding>, CliError> {
    if filter.is_none() && !dissect {
        return Ok(None);
    }
    Ok(Some(Decoding {
        frames: filtering::frame_decoder(registry, filter, max_frame_bytes)?,
        publish_layers: dissect,
    }))
}

/// Which source frames a run keeps, before any frame is decoded for display.
#[derive(Clone, Copy)]
pub(super) struct Selection<'a> {
    pub(super) bounds: Option<core::frame::TimeBounds>,
    pub(super) frames: &'a FrameSelection,
    pub(super) decoding: Option<&'a Decoding>,
}

impl Selection<'_> {
    /// Position and time selectors only; decoding for `--filter` is separate.
    pub(super) fn keeps(&self, number: u64, frame: &core::frame::Frame) -> bool {
        self.frames.keeps(number)
            && self
                .bounds
                .is_none_or(|bounds| bounds.contains(frame.timestamp))
    }

    pub(super) fn is_unrestricted(&self) -> bool {
        self.decoding.is_none() && self.bounds.is_none() && self.frames.is_unrestricted()
    }

    pub(super) fn matches(
        &self,
        number: u64,
        frame: &core::frame::Frame,
    ) -> Result<bool, CliError> {
        if !self.keeps(number, frame) {
            return Ok(false);
        }
        let Some(decoding) = self.decoding else {
            return Ok(true);
        };
        decoding
            .frames
            .decode_selected(number, frame)
            .map(|decoded| decoded.is_some())
            .map_err(|error| filtering::frame_error(number, error))
    }
}

pub(super) fn account_frame(
    budget: &mut capture::Budget,
    frame: &core::frame::Frame,
) -> Result<u64, CliError> {
    crate::cancellation::check()?;
    budget
        .charge(frame.captured_length())
        .map_err(CliError::classified)?;
    Ok(budget.frames())
}
