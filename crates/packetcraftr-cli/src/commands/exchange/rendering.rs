// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output;

use crate::errors::CliError;
use crate::rendering::{
    emit_aggregate_with_stats, emit_next, emit_with_stats, render_diagnostics_text,
    write_capture_file, write_stdout_line,
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

pub(super) fn render_stream(result: packetcraftr::exchange::Result) -> Result<(), CliError> {
    let (result, diagnostics, stats) =
        output::exchange::Result::try_from_exchange(result).map_err(CliError::classified)?;
    let output::exchange::Result {
        sent,
        responses,
        unanswered,
        unsolicited,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    render_sent(sent, &mut sequence)?;
    for response in responses {
        emit_next(
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
        emit_next(
            output::contract::Command::Exchange,
            &mut sequence,
            output::exchange::Event::Unanswered {
                request_index: *request_index,
            },
        )?;
    }
    render_unmatched(unsolicited, undecoded, &mut sequence)?;
    emit_with_stats(
        output::contract::Command::Exchange,
        sequence,
        output::exchange::Event::Complete { unanswered },
        diagnostics,
        stats,
    )
}

fn render_sent(sent: Vec<output::frame::Wire>, sequence: &mut u64) -> Result<(), CliError> {
    for (request_index, frame) in sent.into_iter().enumerate() {
        let request_index = u64::try_from(request_index)
            .map_err(|_| CliError::classified(output::contract::Error::SequenceOverflow))?;
        emit_next(
            output::contract::Command::Exchange,
            sequence,
            output::exchange::Event::Sent {
                request_index,
                frame,
            },
        )?;
    }
    Ok(())
}

fn render_unmatched(
    unsolicited: Vec<output::frame::Decoded>,
    undecoded: Vec<output::frame::Captured>,
    sequence: &mut u64,
) -> Result<(), CliError> {
    for frame in unsolicited {
        emit_next(
            output::contract::Command::Exchange,
            sequence,
            output::exchange::Event::Unsolicited { frame },
        )?;
    }
    for frame in undecoded {
        emit_next(
            output::contract::Command::Exchange,
            sequence,
            output::exchange::Event::Undecoded { frame },
        )?;
    }
    Ok(())
}
