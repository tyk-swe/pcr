// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};

use packetcraftr::{
    analysis::pcap::{Format, Writer},
    core::frame::Frame,
    output,
};

use super::super::errors::CliError;
use super::LinkCaptureWriter;

pub(crate) fn capture_file_format(format: output::contract::Format) -> Result<Format, CliError> {
    match format {
        output::contract::Format::Pcap => Ok(Format::Pcap),
        output::contract::Format::PcapNg => Ok(Format::PcapNg),
        _ => Err(CliError::new(
            70,
            "capture-file renderer received a non-capture format",
        )),
    }
}

pub(crate) fn write_capture_file(
    format: output::contract::Format,
    frames: impl IntoIterator<Item = Frame>,
) -> Result<(), CliError> {
    write_raw(&encode(format, frames)?)
}

fn encode(
    format: output::contract::Format,
    frames: impl IntoIterator<Item = Frame>,
) -> Result<Vec<u8>, CliError> {
    let format = capture_file_format(format)?;
    let mut frames = frames.into_iter();
    let first = frames.next().ok_or_else(|| {
        CliError::new(
            2,
            "capture-file output requires at least one captured or transmitted frame",
        )
    })?;
    let writer = match format {
        Format::Pcap => Writer::new(Vec::new(), format, first.link_type),
        Format::PcapNg => Writer::pcapng(Vec::new()),
    }
    .map_err(|source| CliError::new(5, format!("initialize capture output failed: {source}")))?;
    let mut output = LinkCaptureWriter::new(writer);
    for frame in std::iter::once(first).chain(frames) {
        output
            .write_link_mapped(frame)
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))?;
    }
    Ok(output.into_inner())
}

pub(crate) fn write_raw(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}
