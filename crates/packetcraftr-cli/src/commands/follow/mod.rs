// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use packetcraftr::{analysis, output};

use self::arguments::{Args, Direction};
use super::super::input::open_capture;
use super::offline_analysis::{Prepared, prepare};
use crate::error::{FOLLOW_STREAM, failure};
use crate::rendering::NdjsonStream;
use packetcraftr::BoundaryError;

use analysis::expert::StreamTransport;
use analysis::follow::{Chunk, Collector, Selector};
use rendering::State;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), BoundaryError> {
    let selector = parse_stream(&arguments.stream)?;
    if format == output::contract::Format::Raw && arguments.direction == Direction::Both {
        return Err(failure(
            FOLLOW_STREAM,
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
    let Prepared {
        registry,
        filter,
        limits,
    } = prepare(arguments.limits, Some(&source))?;
    let filter = filter.expect("follow always prepares a stream filter");
    let mut reader = open_capture(&arguments.path, arguments.limits.capture)?;

    let options = analysis::Options {
        filter: Some(&filter),
        // Only TCP needs reassembly; UDP chunks come straight from frames.
        tcp_events: selector.transport == StreamTransport::Tcp,
        limits,
    };
    let mut collector = Collector::new(selector);
    let direction = arguments.direction;
    let mut state = State::default();
    let run_summary = analysis::run(&mut reader, registry, &options, |record| {
        for chunk in collector.observe(&record) {
            if !direction_matches(direction, &chunk) {
                continue;
            }
            rendering::render_record(format, chunk, &mut state, stream)?;
        }
        Ok(())
    })
    .map_err(BoundaryError::from_error)?;
    let summary = collector.finish(&run_summary.trailing_tcp_events);

    match format {
        output::contract::Format::Text => rendering::render_text(selector, &summary),
        output::contract::Format::Json => rendering::render_aggregate(selector, summary, state),
        output::contract::Format::Ndjson => rendering::render_stream(selector, summary, stream),
        output::contract::Format::Hex | output::contract::Format::Raw => {
            rendering::render_payload_warning(&summary)
        }
        _ => unreachable!("the format contract admits only text, json, ndjson, hex, and raw"),
    }
}

fn direction_matches(direction: Direction, chunk: &Chunk) -> bool {
    match direction {
        Direction::Both => true,
        Direction::Client => chunk.direction == analysis::follow::Direction::ClientToServer,
        Direction::Server => chunk.direction == analysis::follow::Direction::ServerToClient,
    }
}

/// Parses a `tcp:INDEX` or `udp:INDEX` conversation spec.
fn parse_stream(spec: &str) -> Result<Selector, BoundaryError> {
    let invalid = || {
        failure(
            FOLLOW_STREAM,
            format!("invalid --stream '{spec}': expected tcp:INDEX or udp:INDEX"),
        )
    };
    let (transport, index) = spec.split_once(':').ok_or_else(invalid)?;
    let transport = match transport {
        "tcp" => StreamTransport::Tcp,
        "udp" => StreamTransport::Udp,
        _ => return Err(invalid()),
    };
    let index = index.parse::<u64>().map_err(|_| invalid())?;
    Ok(Selector { transport, index })
}
