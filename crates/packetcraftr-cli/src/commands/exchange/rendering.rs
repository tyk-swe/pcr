// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output;

use crate::errors::CliError;
use crate::rendering::{
    NdjsonStream, emit_aggregate_with_stats, render_diagnostics_text, write_capture_file,
    write_stdout_line,
};

pub(super) fn render_text(result: &packetcraftr::exchange::Result) -> Result<(), CliError> {
    let mut diagnostics = result.diagnostics.clone();
    for sent in &result.sent {
        diagnostics.extend(sent.built().diagnostics.clone());
    }
    write_stdout_line(format_args!(
        "sent={} responses={} unanswered={} unsolicited={} undecoded={} bytes={}",
        result.sent.len(),
        result.responses.len(),
        result.unanswered.len(),
        result.unsolicited.len(),
        result.undecoded.len(),
        result.stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

pub(super) fn render_capture(
    result: &packetcraftr::exchange::Result,
    format: output::contract::Format,
) -> Result<(), CliError> {
    let mut frames = result
        .sent
        .iter()
        .map(|sent| sent.frame().clone())
        .chain(
            result
                .responses
                .iter()
                .map(|response| response.response.frame.clone()),
        )
        .chain(result.unsolicited.iter().map(|packet| packet.frame.clone()))
        .chain(result.undecoded.iter().cloned())
        .collect::<Vec<_>>();
    frames.sort_by_key(|frame| frame.timestamp);
    write_capture_file(format, frames)
}

pub(super) fn render_aggregate(result: packetcraftr::exchange::Result) -> Result<(), CliError> {
    let (result, diagnostics, stats) =
        output::exchange::Result::try_from_exchange(result).map_err(CliError::classified)?;
    emit_aggregate_with_stats(
        output::contract::Command::Exchange,
        result,
        diagnostics,
        stats,
    )
}

pub(super) fn render_stream(
    result: packetcraftr::exchange::Result,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let (result, diagnostics, stats) =
        output::exchange::Result::try_from_exchange(result).map_err(CliError::classified)?;
    let output::exchange::Result {
        sent,
        responses,
        unanswered,
        unsolicited,
        undecoded,
    } = result;
    render_sent(sent, stream)?;
    for response in responses {
        stream.emit_data(
            output::exchange::Event::Response {
                request_index: response.request_index,
                response: response.response,
                latency: response.latency,
            },
            Vec::new(),
        )?;
    }
    for request_index in &unanswered {
        stream.emit_data(
            output::exchange::Event::Unanswered {
                request_index: *request_index,
            },
            Vec::new(),
        )?;
    }
    render_unmatched(unsolicited, undecoded, stream)?;
    stream.complete_with_stats(
        output::exchange::Event::Complete { unanswered },
        diagnostics,
        stats,
    )
}

fn render_sent(sent: Vec<output::frame::Wire>, stream: &mut NdjsonStream) -> Result<(), CliError> {
    for (request_index, frame) in sent.into_iter().enumerate() {
        let request_index = u64::try_from(request_index).map_err(|_| {
            CliError::new(
                70,
                "exchange request index exceeds the unsigned 64-bit domain",
            )
        })?;
        stream.emit_data(
            output::exchange::Event::Sent {
                request_index,
                frame,
            },
            Vec::new(),
        )?;
    }
    Ok(())
}

fn render_unmatched(
    unsolicited: Vec<output::frame::Decoded>,
    undecoded: Vec<output::frame::Captured>,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    for frame in unsolicited {
        stream.emit_data(output::exchange::Event::Unsolicited { frame }, Vec::new())?;
    }
    for frame in undecoded {
        stream.emit_data(output::exchange::Event::Undecoded { frame }, Vec::new())?;
    }
    Ok(())
}
