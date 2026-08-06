// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr::{analysis, output};

use self::arguments::{CliFollowDirection, FollowArgs};
use super::super::errors::CliError;
use super::super::rendering::{
    emit_json, emit_json_compact, emit_stderr_message, write_raw, write_stdout_line,
};
use super::offline_analysis::{
    PreparedOfflineAnalysis, open_offline_reader, prepare_offline_analysis,
};

use analysis::expert::StreamTransport;
use analysis::follow::{Chunk, FollowCollector, Selector};

pub(super) fn run(arguments: FollowArgs, output: output::contract::Format) -> Result<(), CliError> {
    output::contract::Command::Follow
        .require_format(output)
        .map_err(CliError::classified)?;
    let selector = parse_stream(&arguments.stream)?;
    if output == output::contract::Format::Raw && arguments.direction == CliFollowDirection::Both {
        return Err(CliError::new(
            2,
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
    let PreparedOfflineAnalysis {
        registry,
        filter,
        limits,
    } = prepare_offline_analysis(arguments.limits, Some(&source))?;
    let filter = filter.expect("follow always prepares a stream filter");
    let mut reader = open_offline_reader(&arguments.path, arguments.limits.capture)?;

    let options = analysis::Options {
        filter: Some(&filter),
        // Only TCP needs reassembly; UDP chunks come straight from frames.
        tcp_events: selector.transport == StreamTransport::Tcp,
        limits,
    };
    let mut collector = FollowCollector::new(selector);
    let direction = arguments.direction;
    let mut sequence = 0_u64;
    let mut retained: Vec<output::follow::Chunk> = Vec::new();
    let run_summary = analysis::run(&mut reader, registry, &options, |record| {
        for chunk in collector.observe(&record) {
            if !direction_matches(direction, &chunk) {
                continue;
            }
            emit_chunk(output, chunk, &mut sequence, &mut retained)
                .map_err(CliError::into_boundary_error)?;
        }
        Ok(())
    })
    .map_err(|error| {
        let error = CliError::classified(error);
        // Streamed records are numbered by emission, not by capture frame,
        // so a terminal stream error continues that numbering.
        if matches!(output, output::contract::Format::Ndjson) {
            error.at_sequence(sequence)
        } else {
            error
        }
    })?;
    let summary = collector.finish(&run_summary.trailing_tcp_events);

    match output {
        output::contract::Format::Text => {
            let transport = transport_name(selector.transport);
            match &summary.client_flow {
                Some(flow) => write_stdout_line(format_args!(
                    "followed {transport} stream {}: client {}:{} sent {} byte(s), \
                     server {}:{} sent {} byte(s), {} byte(s) undelivered in {} frame(s)",
                    selector.index,
                    flow.source,
                    flow.source_port,
                    summary.client_bytes,
                    flow.destination,
                    flow.destination_port,
                    summary.server_bytes,
                    summary.undelivered_bytes,
                    summary.frames,
                )),
                None => write_stdout_line(format_args!(
                    "followed {transport} stream {}: no frames",
                    selector.index
                )),
            }
        }
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Follow,
            output::follow::Result::from_summary(
                selector.transport.into(),
                selector.index,
                summary,
                retained,
            ),
            Vec::new(),
        )),
        output::contract::Format::Ndjson => {
            // Every direction-selected chunk was already streamed; the
            // terminal record carries only the totals and an empty chunk
            // list, so NDJSON does not retain payloads.
            emit_json_compact(&output::envelope::Stream::success(
                output::contract::Command::Follow,
                sequence,
                output::follow::Result::from_summary(
                    selector.transport.into(),
                    selector.index,
                    summary,
                    Vec::new(),
                ),
                Vec::new(),
            ))
            .map_err(|error| error.at_sequence(sequence))
        }
        output::contract::Format::Hex | output::contract::Format::Raw => {
            // Standard output stays pure payload, so incompleteness is
            // reported out of band rather than silently swallowed.
            if summary.undelivered_bytes > 0 {
                emit_stderr_message(&format!(
                    "warning: {} byte(s) were captured but stranded behind \
                     missing segments and are not part of this output",
                    summary.undelivered_bytes
                ))?;
            }
            Ok(())
        }
        _ => unreachable!("the format contract admits only text, json, ndjson, hex, and raw"),
    }
}

/// Streams or retains one chunk, depending on the output format.
fn emit_chunk(
    output: output::contract::Format,
    chunk: Chunk,
    sequence: &mut u64,
    retained: &mut Vec<output::follow::Chunk>,
) -> Result<(), CliError> {
    match output {
        output::contract::Format::Text => write_stdout_line(format_args!(
            "{} #{} {}",
            direction_marker(&chunk),
            chunk.number,
            chunk.bytes.escape_ascii()
        )),
        output::contract::Format::Hex => {
            let rendered = output::follow::Chunk::from(chunk.clone());
            write_stdout_line(format_args!(
                "{} #{} {}",
                direction_marker(&chunk),
                rendered.frame,
                rendered.bytes_hex
            ))
        }
        output::contract::Format::Raw => write_raw(&chunk.bytes),
        output::contract::Format::Json => {
            retained.push(chunk.into());
            Ok(())
        }
        output::contract::Format::Ndjson => {
            emit_json_compact(&output::envelope::Stream::success(
                output::contract::Command::Follow,
                *sequence,
                output::follow::Chunk::from(chunk),
                Vec::new(),
            ))
            .map_err(|error| error.at_sequence(*sequence))?;
            *sequence = sequence.checked_add(1).ok_or_else(|| {
                CliError::classified(output::contract::Error::SequenceOverflow)
                    .at_sequence(*sequence)
            })?;
            Ok(())
        }
        _ => unreachable!("the format contract admits only text, json, ndjson, hex, and raw"),
    }
}

fn direction_matches(direction: CliFollowDirection, chunk: &Chunk) -> bool {
    match direction {
        CliFollowDirection::Both => true,
        CliFollowDirection::Client => {
            chunk.direction == analysis::follow::Direction::ClientToServer
        }
        CliFollowDirection::Server => {
            chunk.direction == analysis::follow::Direction::ServerToClient
        }
    }
}

fn direction_marker(chunk: &Chunk) -> &'static str {
    match chunk.direction {
        analysis::follow::Direction::ClientToServer => ">",
        analysis::follow::Direction::ServerToClient => "<",
    }
}

fn transport_name(transport: StreamTransport) -> &'static str {
    match transport {
        StreamTransport::Tcp => "tcp",
        StreamTransport::Udp => "udp",
    }
}

/// Parses a `tcp:INDEX` or `udp:INDEX` conversation spec.
fn parse_stream(spec: &str) -> Result<Selector, CliError> {
    let invalid = || {
        CliError::new(
            2,
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
