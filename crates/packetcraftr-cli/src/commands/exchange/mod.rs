// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{client, output, packet};

use self::arguments::ExchangeArgs;
use super::super::errors::CliError;
use super::super::rendering::{
    emit_json, emit_json_compact, emit_stream_record, render_diagnostics_text, write_capture_file,
    write_stdout_line,
};
use super::super::system::{default_registry_arc, prepare_route_request, system_client};
use super::send::arguments::SendArgs;

pub(super) fn run(
    arguments: ExchangeArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let ExchangeArgs {
        send,
        timeout_ms,
        max_responses,
        max_unsolicited,
        limits,
    } = arguments;
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
        policy,
    } = send;
    let limits = limits.into_limits();
    let mut options = client::exchange::Options {
        timeout: Duration::from_millis(timeout_ms),
        max_template_packets: 1,
        max_responses,
        max_unsolicited,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        ..client::exchange::Options::default()
    };
    options.decode.max_packet_size = limits.snap_length;
    // Validate before packet parsing can trigger hostname/interface work.
    options.validate().map_err(CliError::classified)?;

    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, policy.into_policy(), &registry)?;
    options.send = client::send::Options {
        destination: request.destination,
        plan: request.options,
        build: packet::build::Options {
            mode: mode.into(),
            ..packet::build::Options::default()
        },
        allow_permissive_live,
    };
    let client = system_client(Arc::clone(&registry), request.policy);
    let result = client
        .exchange(&packet::template::Template::new(request.packet), options)
        .map_err(CliError::classified)?;

    if matches!(
        output,
        output::contract::Format::Pcap | output::contract::Format::Pcapng
    ) {
        let frames = result
            .sent_evidence
            .iter()
            .cloned()
            .chain(
                result
                    .responses
                    .iter()
                    .map(|response| response.response.frame.clone()),
            )
            .chain(result.unsolicited.iter().map(|packet| packet.frame.clone()))
            .chain(result.undecoded.iter().cloned())
            .collect::<Vec<_>>();
        let mut frames = frames;
        frames.sort_by_key(|frame| frame.timestamp);
        return write_capture_file(output, frames);
    }

    let (result, diagnostics, stats) =
        output::exchange::Result::try_from_exchange(result).map_err(CliError::classified)?;
    match output {
        output::contract::Format::Text => {
            write_stdout_line(format_args!(
                "sent={} responses={} unanswered={} unsolicited={} undecoded={} bytes={}",
                result.sent.len(),
                result.responses.len(),
                result.unanswered.len(),
                result.unsolicited.len(),
                result.undecoded.len(),
                stats.bytes
            ))?;
            render_diagnostics_text(&diagnostics)
        }
        output::contract::Format::Json => emit_json(
            &output::envelope::Aggregate::success(
                output::contract::Command::Exchange,
                result,
                diagnostics,
            )
            .with_stats(stats),
        ),
        output::contract::Format::Ndjson => render_exchange_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Exchange,
                format: output,
            },
        )),
    }
}

fn render_exchange_stream(
    result: output::exchange::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    let output::exchange::Result {
        sent,
        responses,
        unanswered,
        unsolicited,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    for (request_index, frame) in sent.into_iter().enumerate() {
        let request_index = u64::try_from(request_index)
            .map_err(|_| CliError::classified(output::contract::Error::SequenceOverflow))?;
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::exchange::Event::Sent {
                request_index,
                frame,
            },
        )?;
    }
    for response in responses {
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::exchange::Event::Response {
                request_index: response.request_index,
                response: response.response,
                latency: response.latency,
            },
        )?;
    }
    for request_index in &unanswered {
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::exchange::Event::Unanswered {
                request_index: *request_index,
            },
        )?;
    }
    for frame in unsolicited {
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::exchange::Event::Unsolicited { frame },
        )?;
    }
    for frame in undecoded {
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::exchange::Event::Undecoded { frame },
        )?;
    }
    emit_json_compact(
        &output::envelope::Stream::success(
            output::contract::Command::Exchange,
            sequence,
            output::exchange::Event::Complete { unanswered },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}
