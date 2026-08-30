// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

pub(super) mod arguments;
mod rendering;

use packetcraftr::{analysis, output};

use self::arguments::{Args, Direction};
use super::super::errors::CliError;
use super::super::input::open_capture;
use super::format::FollowFormat;
use super::offline_analysis::{StreamSelector, parse_stream_selector, prepare};
use crate::rendering::StreamEncoder;

use analysis::expert::StreamTransport;
use analysis::follow::{Chunk, Collector, Selector};
use rendering::State;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    let format = FollowFormat::narrow(output::contract::Command::Follow, format)?;
    let StreamSelector { transport, index } = parse_stream_selector(&arguments.stream)?;
    let selector = Selector { transport, index };
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
        match selector.transport {
            StreamTransport::Tcp => "tcp",
            StreamTransport::Udp => "udp",
        },
        selector.index
    );
    let prepared = prepare(arguments.limits, Some(&source))?;
    let mut reader = open_capture(&arguments.path, arguments.limits.capture)?;

    // Only TCP needs reassembly; UDP chunks come straight from frames.
    let options = prepared.options(selector.transport == StreamTransport::Tcp);
    let mut collector = Collector::new(selector);
    let direction = arguments.direction;
    let mut state = State::default();
    let run_summary = analysis::run_with_ip_events(
        &mut reader,
        prepared.registry.clone(),
        &options,
        super::offline_analysis::ip_event_sink(format == FollowFormat::Ndjson, stream.clone()),
        |record| {
            for chunk in collector.observe(&record) {
                if !direction_matches(direction, &chunk) {
                    continue;
                }
                rendering::render_record(format, chunk, &mut state, stream)
                    .map_err(CliError::into_boundary_error)?;
            }
            Ok(())
        },
    )
    .map_err(CliError::classified)?;
    let summary = collector.finish(&run_summary.trailing_tcp_events);

    match format {
        FollowFormat::Text => rendering::render_text(selector, &summary),
        FollowFormat::Json => {
            rendering::render_aggregate(selector, summary, state, &run_summary.ip_reassembly)
        }
        FollowFormat::Ndjson => {
            rendering::render_stream(selector, summary, &run_summary.ip_reassembly, stream)
        }
        FollowFormat::Hex | FollowFormat::Raw => rendering::render_payload_warning(&summary),
    }
}

fn direction_matches(direction: Direction, chunk: &Chunk) -> bool {
    match direction {
        Direction::Both => true,
        Direction::Client => chunk.direction == analysis::follow::Direction::ClientToServer,
        Direction::Server => chunk.direction == analysis::follow::Direction::ServerToClient,
    }
}
