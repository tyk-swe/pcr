// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::capture_file::Format;
use packetcraftr_core::diagnostic::Diagnostic;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{
    StreamEncoder, render_diagnostics_text, write_capture_file, write_stdout_line,
};

pub(super) fn render_text(result: &packetcraftr::exchange::Aggregate) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "sent={} responses={} unanswered={} unsolicited={} undecoded={} bytes={}",
        result.sent.len(),
        result.responses.len(),
        result.unanswered.len(),
        result.unsolicited.len(),
        result.undecoded.len(),
        result.stats.bytes
    ))?;
    render_diagnostics_text(&text_diagnostics(result))
}

fn text_diagnostics(result: &packetcraftr::exchange::Aggregate) -> Vec<Diagnostic> {
    let mut diagnostics = result.diagnostics.clone();
    for sent in &result.sent {
        for diagnostic in &sent.built().diagnostics {
            packetcraftr_core::diagnostic::push_once(&mut diagnostics, diagnostic.clone());
        }
    }
    diagnostics
}

pub(super) fn render_capture(
    result: &packetcraftr::exchange::Aggregate,
    format: Format,
    compression: crate::command_options::Compression,
) -> Result<(), CliError> {
    let frames = stable_timestamp_order(
        result
            .sent
            .iter()
            .map(|sent| sent.frame())
            .chain(
                result
                    .responses
                    .iter()
                    .map(|response| &response.response.frame),
            )
            .chain(result.unsolicited.iter().map(|packet| &packet.frame))
            .chain(result.undecoded.iter()),
    );
    write_capture_file(format, frames.into_iter().cloned(), compression)
}

fn stable_timestamp_order<'a>(
    frames: impl IntoIterator<Item = &'a packetcraftr_core::frame::Frame>,
) -> Vec<&'a packetcraftr_core::frame::Frame> {
    let mut frames = frames.into_iter().collect::<Vec<_>>();
    frames.sort_by_key(|frame| frame.timestamp);
    frames
}

pub(super) fn emit_event(
    event: packetcraftr::exchange::Event,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let published = output::envelope::Published::<output::exchange::Event>::try_from(event)
        .map_err(CliError::classified)?;
    Ok(stream.emit_published(published)?)
}

pub(super) fn render_complete(
    summary: packetcraftr::exchange::Report,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(stream.complete_published(
        output::envelope::Published::<output::exchange::Event>::from(summary),
    )?)
}
