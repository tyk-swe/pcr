// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output::contract::FollowFormat;

use packetcraftr_core::error::Kind;

pub(super) mod arguments;
mod rendering;
mod write;

use packetcraftr_core::analysis;

use self::arguments::{Args, Direction};
use super::offline_analysis::{parse_stream_selector, prepare, require_selected_stream};
use crate::errors::CliError;
use crate::rendering::StreamEncoder;

use analysis::follow::{Chunk, Collector};
use rendering::State;

pub(super) fn run(
    arguments: Args,
    format: FollowFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let selector = parse_stream_selector(&arguments.stream)?;
    if format == FollowFormat::Raw && arguments.direction == Direction::Both {
        return Err(CliError::new(
            Kind::Cli,
            "raw output interleaves both directions indistinguishably; \
             choose --direction client or --direction server",
        ));
    }
    let prepared = prepare(arguments.limits, None, &arguments.decode)?;
    crate::command_options::validate_output_bytes(arguments.max_application_output_bytes)?;
    // Stage one file per selected direction before any capture is read, so a
    // missing or unwritable directory fails before the run.
    let mut files = arguments
        .write
        .as_deref()
        .map(|directory| {
            write::DirectionFiles::stage(
                directory,
                selector,
                arguments.direction,
                arguments.max_application_output_bytes,
            )
        })
        .transpose()?;
    let (mut reader, session) = prepared.open_session(
        &arguments.path,
        arguments.limits.capture.reader,
        Collector::new(selector),
        Some(selector),
    )?;
    let direction = arguments.direction;
    let mut state = State::new(arguments.limits.capture.retention_ceiling());
    let mut sink = |chunk: Chunk| -> Result<(), packetcraftr_core::error::BoundaryError> {
        if direction_matches(direction, &chunk) {
            if let Some(files) = files.as_mut() {
                files.write(&chunk).map_err(CliError::into_boundary_error)?;
            }
            rendering::render_record(format, chunk, &mut state, stream)
                .map_err(CliError::into_boundary_error)?;
        }
        Ok(())
    };
    let pass = session
        .observe(
            &mut reader,
            super::offline_analysis::ip_event_sink(format, stream),
            &mut sink,
        )
        .map_err(CliError::classified)?;
    // The verdict precedes collector finish and publication, as before.
    require_selected_stream(pass.selected_stream())?;
    let outcome = pass.finish(&mut sink).map_err(CliError::classified)?;
    let summary = outcome.summary;
    let run_summary = outcome.run;
    let written = files
        .map(write::DirectionFiles::publish)
        .transpose()?
        .unwrap_or_default();

    match format {
        FollowFormat::Text => rendering::render_text(selector, &summary, &written),
        FollowFormat::Json => rendering::render_aggregate(
            selector,
            summary,
            state,
            &run_summary.ip_reassembly,
            written,
        ),
        FollowFormat::Ndjson => rendering::render_stream(
            selector,
            summary,
            &run_summary.ip_reassembly,
            stream,
            written,
        ),
        FollowFormat::Hex | FollowFormat::Raw => {
            rendering::render_written(&written)?;
            rendering::render_payload_warning(&summary)
        }
    }
}

fn direction_matches(direction: Direction, chunk: &Chunk) -> bool {
    match direction {
        Direction::Both => true,
        Direction::Client => chunk.direction == analysis::follow::PeerDirection::ClientToServer,
        Direction::Server => chunk.direction == analysis::follow::PeerDirection::ServerToClient,
    }
}
