// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::ReadFormat;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{
    StreamEncoder, captured_frame_text, render_diagnostics_text, render_dns_records, spaced_hex,
    write_plain_line, write_stdout_line,
};

pub(super) fn render_record(
    record: output::read::Frame,
    format: ReadFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let output::read::Frame {
        source_frame,
        frame,
        decoded,
    } = &record;
    match format {
        ReadFormat::Text => render_frame_text(*source_frame, frame, decoded.as_ref()),
        ReadFormat::Hex => write_plain_line(format_args!("{}", frame.bytes_hex())),
        ReadFormat::Ndjson => Ok(stream.emit_data(output::read::Event::Frame(record), Vec::new())?),
        ReadFormat::Json
        | ReadFormat::Csv
        | ReadFormat::Tsv
        | ReadFormat::Pcap
        | ReadFormat::PcapNg => Err(CliError::new(
            packetcraftr_core::error::Kind::Internal,
            "capture-file output returned before frame rendering",
        )),
    }
}

/// One frame line for text output, with the dissected stack and its
/// diagnostics when the command decoded the frame.
pub(crate) fn render_frame_text(
    source_frame: output::frame::SourceFrame,
    frame: &output::frame::Captured,
    decoded: Option<&output::frame::Stack>,
) -> Result<(), CliError> {
    match decoded {
        None => write_stdout_line(format_args!(
            "{source_frame}: {}",
            captured_frame_text(frame)
        )),
        Some(decoded) => {
            write_stdout_line(format_args!(
                "{source_frame}: dlt={} caplen={} wirelen={} layers={} {}",
                frame.link_type,
                frame.captured_length,
                frame.original_length,
                decoded
                    .packet
                    .layers
                    .iter()
                    .map(|layer| layer.protocol.as_str())
                    .collect::<Vec<_>>()
                    .join("/"),
                spaced_hex(frame.bytes())
            ))?;
            render_dns_records(&decoded.packet)?;
            if !decoded.diagnostics.is_empty() {
                write_stdout_line(format_args!("{source_frame}: diagnostics:"))?;
                render_diagnostics_text(&decoded.diagnostics)?;
            }
            Ok(())
        }
    }
}
