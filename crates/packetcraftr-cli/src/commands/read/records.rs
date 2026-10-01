// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;

use packetcraftr_core as core;
use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::Reader;

use super::rendering::render_record;
use super::selection::{Decoding, Selection, account_frame};
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::commands::increment_counter;
use crate::errors::CliError;
use crate::filtering;
use crate::output;
use crate::output::contract::ReadFormat;
use crate::rendering::{FieldTree, StreamEncoder};

pub(super) fn run(
    reader: &mut Reader<impl Read>,
    limits: OfflineCaptureLimitsArgs,
    selection: Selection<'_>,
    format: ReadFormat,
    stream: &StreamEncoder,
    mut tree: Option<&mut FieldTree>,
) -> Result<(), CliError> {
    let mut budget = capture::Budget::new(limits.stream_limits()).map_err(CliError::classified)?;
    let mut frames_matched = 0;
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        let source_frame = account_frame(&mut budget, &frame)?;
        if !selection.keeps(source_frame, &frame) {
            continue;
        }
        let Some(record) = convert_frame(frame, source_frame, selection.decoding)? else {
            continue;
        };
        render_record(record, format, stream, tree.as_deref_mut())?;
        frames_matched = increment_counter(frames_matched, "read matched-frame count")?;
    }
    if format == ReadFormat::Ndjson {
        stream.complete(
            output::read::Event::from(output::read::Totals::from((&budget, frames_matched))),
            Vec::new(),
        )?;
    }
    Ok(())
}

fn convert_frame(
    frame: core::frame::Frame,
    source_frame: u64,
    decoding: Option<&Decoding>,
) -> Result<Option<output::read::Frame>, CliError> {
    let Some(decoding) = decoding else {
        return output::read::Frame::try_from((source_frame, frame))
            .map(Some)
            .map_err(CliError::classified);
    };
    let Some(decoded) = decoding
        .frames
        .decode_selected(source_frame, &frame)
        .map_err(|error| filtering::frame_error(source_frame, error))?
    else {
        return Ok(None);
    };
    if decoding.publish_layers {
        output::read::Frame::try_from((source_frame, frame, &decoded))
    } else {
        output::read::Frame::try_from((source_frame, frame))
    }
    .map(Some)
    .map_err(CliError::classified)
}
