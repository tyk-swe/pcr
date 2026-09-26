// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::ReadFormat;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{StreamEncoder, render_frame_text, write_plain_line};

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
