// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output;

use crate::rendering::{
    NdjsonStream, emit_aggregate_with_stats, render_diagnostics_text, write_capture_file,
    write_stdout_line,
};
use packetcraftr::BoundaryError;

pub(super) fn render_text(result: &packetcraftr::exchange::Result) -> Result<(), BoundaryError> {
    let mut diagnostics = result.diagnostics.clone();
    for sent in &result.sent {
        diagnostics.extend(sent.built().diagnostics.iter().cloned());
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
) -> Result<(), BoundaryError> {
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

pub(super) fn render_aggregate(
    result: packetcraftr::exchange::Result,
) -> Result<(), BoundaryError> {
    let (result, diagnostics, stats) =
        output::exchange::Result::try_from_exchange(result).map_err(BoundaryError::from_error)?;
    emit_aggregate_with_stats(
        output::contract::Command::Exchange,
        result,
        diagnostics,
        stats,
    )
}

pub(super) fn render_complete(
    summary: packetcraftr::exchange::Summary,
    stream: &NdjsonStream,
) -> Result<(), BoundaryError> {
    let (event, diagnostics, stats) = output::exchange::Event::complete_from_exchange(summary);
    stream.complete_with_stats(event, diagnostics, stats)
}
