// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output::contract::Format;

use packetcraftr::output;

use crate::errors::CliError;
use crate::rendering::{
    StreamEncoder, captured_frame_text, spaced_hex, write_plain_line, write_stdout_line,
};

pub(super) fn render_record(
    record: output::read::Frame,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let output::read::Frame {
        source_frame,
        frame,
        decoded,
    } = &record;
    match format {
        Format::Text => match decoded {
            None => write_stdout_line(format_args!(
                "{source_frame}: {}",
                captured_frame_text(frame)
            )),
            Some(decoded) => write_stdout_line(format_args!(
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
            )),
        },
        Format::Hex => write_plain_line(format_args!("{}", frame.bytes_hex())),
        Format::Ndjson => Ok(stream.emit_data(output::read::Event::Frame(record), Vec::new())?),
        _ => unreachable!("capture-file output returned before frame rendering"),
    }
}
