// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output::contract::FollowFormat;

use packetcraftr_core::error::Kind;

pub(super) mod arguments;
mod rendering;
mod write;

use packetcraftr_core::analysis;

use self::arguments::{Args, Direction};
use super::offline_analysis::{parse_stream_selector, prepare};
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::StreamEncoder;

use analysis::StreamTransport;
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
    // The stream filter narrows reassembly to the followed conversation
    // while indices stay capture-global, so the index stats reports is the
    // index extracted here.
    let source = format!(
        "{}.stream == {}",
        selector.transport.as_str(),
        selector.index
    );
    let prepared = prepare(arguments.limits, Some(&source), &arguments.decode)?;
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
    let mut reader = open_capture(&arguments.path, arguments.limits.capture.reader)?;

    // Only TCP needs reassembly; UDP chunks come straight from frames.
    let options = prepared.options(selector.transport == StreamTransport::Tcp);
    let mut collector = Collector::new(selector);
    let direction = arguments.direction;
    let mut state = State::new(arguments.limits.capture.retention_ceiling());
    let run_summary = analysis::run_with_ip_events(
        &mut reader,
        prepared.registry.clone(),
        &options,
        super::offline_analysis::ip_event_sink(
            (format == FollowFormat::Ndjson).then(|| stream.clone()),
        ),
        |record| {
            for chunk in collector.observe(&record) {
                if !direction_matches(direction, &chunk) {
                    continue;
                }
                if let Some(files) = files.as_mut() {
                    files.write(&chunk).map_err(CliError::into_boundary_error)?;
                }
                rendering::render_record(format, chunk, &mut state, stream)
                    .map_err(CliError::into_boundary_error)?;
            }
            Ok(())
        },
    )
    .map_err(CliError::classified)?;
    // Stream indices are assigned before filtering, including frames without payload.
    if run_summary.frames_matched == 0 {
        return Err(CliError::new(
            Kind::Cli,
            format!(
                "--stream {}:{} is not present",
                selector.transport.as_str(),
                selector.index
            ),
        ));
    }
    let summary = collector.finish(&run_summary);
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
