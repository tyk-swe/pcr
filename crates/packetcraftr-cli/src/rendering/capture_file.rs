// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Read, Seek, SeekFrom, Write};

use packetcraftr::{
    analysis::pcap::{Error as CaptureError, Format, Writer},
    core::{
        error::{Classification, Kind},
        frame::Frame,
    },
};

use super::LinkCaptureWriter;
use crate::errors::CliError;

const COPY_BUFFER_BYTES: usize = 64 * 1024;

trait Spool: Read + Write + Seek {}

impl<T: Read + Write + Seek> Spool for T {}

pub(crate) fn write_capture_file(
    format: Format,
    frames: impl IntoIterator<Item = Frame>,
) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    write_capture_file_with(
        format,
        frames,
        || tempfile::tempfile().map(|file| Box::new(file) as Box<dyn Spool>),
        &mut stdout,
    )
}

fn write_capture_file_with(
    format: Format,
    frames: impl IntoIterator<Item = Frame>,
    create_spool: impl FnOnce() -> io::Result<Box<dyn Spool>>,
    destination: &mut dyn Write,
) -> Result<(), CliError> {
    let mut frames = frames.into_iter();
    let first = frames.next().ok_or_else(|| {
        CliError::new(
            Kind::Cli,
            "capture-file output requires at least one captured or transmitted frame",
        )
    })?;
    let spool = create_spool()
        .map_err(|source| capture_io_error("create temporary capture output failed", source))?;
    let writer = match format {
        Format::Pcap => Writer::new(spool, format, first.link_type),
        Format::PcapNg => Writer::pcapng(spool),
    }
    .map_err(initialize_error)?;
    let mut output = LinkCaptureWriter::new(writer);
    for frame in std::iter::once(first).chain(frames) {
        output.write_link_mapped(frame).map_err(write_error)?;
    }
    output.flush().map_err(write_error)?;

    let mut spool = output.into_inner();
    spool
        .seek(SeekFrom::Start(0))
        .map_err(|source| capture_io_error("rewind temporary capture output failed", source))?;
    copy_spool(&mut *spool, destination)
}

fn copy_spool(spool: &mut dyn Read, destination: &mut dyn Write) -> Result<(), CliError> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = spool
            .read(&mut buffer)
            .map_err(|source| capture_io_error("read temporary capture output failed", source))?;
        if read == 0 {
            break;
        }
        let bytes = buffer.get(..read).ok_or_else(|| {
            CliError::new(
                Kind::Internal,
                "temporary capture read exceeded the copy buffer",
            )
        })?;
        destination
            .write_all(bytes)
            .map_err(|source| stdout_error("write stdout failed", source))?;
    }
    destination
        .flush()
        .map_err(|source| stdout_error("flush stdout failed", source))
}

fn initialize_error(source: CaptureError) -> CliError {
    match source {
        CaptureError::Io(source) => {
            capture_io_error("initialize temporary capture output failed", source)
        }
        source => CliError::new(
            Kind::Io,
            format!("initialize capture output failed: {source}"),
        ),
    }
}

fn write_error(source: CaptureError) -> CliError {
    match source {
        CaptureError::Io(source) => {
            capture_io_error("write temporary capture output failed", source)
        }
        source => CliError::new(Kind::Io, format!("write capture output failed: {source}")),
    }
}

fn capture_io_error(operation: &str, source: io::Error) -> CliError {
    CliError::from_classification(
        Classification::new(
            "io.capture_file",
            Kind::Io,
            Some("inspect temporary storage availability and retry the capture output operation"),
        ),
        format!("{operation}: {source}"),
        vec![source.to_string()],
    )
}

/// The one mapping for a capture-file writer that writes straight to stdout,
/// as `capture` and `replay` do.
///
/// An I/O failure there is a stdout failure and is classified as one, exactly
/// as the spooled `send`/`exchange` path classifies its final copy; anything
/// else keeps the capture error's own classification, so the same stream-limit
/// or metadata failure is reported the same way whichever command hit it.
pub(crate) fn stream_capture_error(operation: &str, source: CaptureError) -> CliError {
    match source {
        CaptureError::Io(source) => stdout_error(operation, source),
        source => CliError::classified(source),
    }
}

pub(crate) fn stdout_error(operation: &str, source: io::Error) -> CliError {
    CliError::from_classification(
        Classification::new(
            "io.stdout",
            Kind::Io,
            Some("restore the stdout consumer or choose a writable output destination"),
        ),
        format!("{operation}: {source}"),
        vec![source.to_string()],
    )
}

pub(crate) fn write_raw(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(Kind::Io, format!("write stdout failed: {source}")))
}

#[cfg(test)]
mod tests;
