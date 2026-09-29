// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Read, Seek, SeekFrom, Write};

use packetcraftr_core::capture_file::{
    Error as CaptureError, Format, Limits, PcapNgOptions, PcapOptions, Writer,
};
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::Frame;

use super::LinkCaptureWriter;
use super::stdout::stdout_error;
use crate::errors::{CliError, source_causes};

const COPY_BUFFER_BYTES: usize = 64 * 1024;

pub(crate) fn write_capture_file(
    format: Format,
    frames: impl IntoIterator<Item = Frame>,
    compression: crate::command_options::Compression,
) -> Result<(), CliError> {
    let stdout = write_capture_file_with(format, frames, tempfile::tempfile, || {
        compression.writer(io::stdout().lock())
    })?;
    drop(stdout.finish().map_err(CliError::classified)?);
    Ok(())
}

/// Encodes every frame into a spool and opens the destination only once the
/// whole capture has encoded, so a failure leaves the destination untouched.
fn write_capture_file_with<S: Read + Write + Seek, D: Write>(
    format: Format,
    frames: impl IntoIterator<Item = Frame>,
    create_spool: impl FnOnce() -> io::Result<S>,
    open_destination: impl FnOnce() -> Result<D, CliError>,
) -> Result<D, CliError> {
    let frames = frames.into_iter().collect::<Vec<_>>();
    let Some(first) = frames.first() else {
        return Err(CliError::new(
            Kind::Usage,
            "capture-file output requires at least one captured or transmitted frame",
        ));
    };
    let link_type = first.link_type;
    let stream_limits = stream_limits(
        frames.len() as u64,
        frames.iter().fold(0_u64, |total, frame| {
            total.saturating_add(u64::from(frame.captured_length()))
        }),
    );
    let spool = create_spool()
        .map_err(|source| capture_io_error("create temporary capture output failed", source))?;
    let writer = match format {
        Format::Pcap => Writer::pcap_with_options(
            spool,
            link_type,
            PcapOptions {
                stream_limits,
                ..PcapOptions::default()
            },
        ),
        Format::PcapNg => Writer::pcapng_with_options(
            spool,
            PcapNgOptions {
                stream_limits,
                ..PcapNgOptions::default()
            },
        ),
    }
    .map_err(initialize_error)?;
    let mut output = LinkCaptureWriter::new(writer);
    for frame in frames {
        output.write_link_mapped(frame).map_err(write_error)?;
    }
    output.flush().map_err(write_error)?;

    let mut spool = output.into_inner();
    spool
        .seek(SeekFrom::Start(0))
        .map_err(|source| capture_io_error("rewind temporary capture output failed", source))?;
    let mut destination = open_destination()?;
    copy_spool(&mut spool, &mut destination)?;
    Ok(destination)
}

/// Stream limits for a capture whose frame set the caller's own budgets have
/// already admitted, so core's default ceiling cannot refuse it after
/// transmission. Zero is not a valid ceiling.
pub(crate) fn stream_limits(max_frames: u64, max_bytes: u64) -> Limits {
    Limits {
        max_frames: max_frames.max(1),
        max_bytes: max_bytes.max(1),
    }
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
        destination
            .write_all(&buffer[..read])
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
        source => CliError::classified(source),
    }
}

fn write_error(source: CaptureError) -> CliError {
    match source {
        CaptureError::Io(source) => {
            capture_io_error("write temporary capture output failed", source)
        }
        source => CliError::classified(source),
    }
}

fn capture_io_error(operation: &str, source: io::Error) -> CliError {
    CliError::from_classification(
        Classification::new(
            "io.capture_file",
            Kind::Io,
            Some("inspect temporary storage availability and retry the capture output operation"),
        ),
        operation,
        source_causes(&source),
    )
}

pub(crate) fn stream_capture_error(operation: &str, source: CaptureError) -> CliError {
    match source {
        CaptureError::Io(source) => stdout_error(operation, source),
        source => CliError::classified(source),
    }
}

#[cfg(test)]
mod tests;
