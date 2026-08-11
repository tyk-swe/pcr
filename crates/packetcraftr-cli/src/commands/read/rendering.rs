// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output;

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, emit_stream, spaced_hex, write_plain_line, write_stdout_line,
};

pub(super) fn render_read_record(
    result: &output::read::Result,
    output_format: output::contract::Format,
    sequence: u64,
) -> Result<(), CliError> {
    match output_format {
        output::contract::Format::Text => match &result.decoded {
            None => write_stdout_line(format_args!(
                "{sequence}: {}",
                captured_frame_text(&result.frame)
            )),
            Some(decoded) => write_stdout_line(format_args!(
                "{sequence}: dlt={} caplen={} wirelen={} layers={} {}",
                result.frame.link_type,
                result.frame.captured_length,
                result.frame.original_length,
                decoded
                    .packet
                    .layers
                    .iter()
                    .map(|layer| layer.protocol.as_str())
                    .collect::<Vec<_>>()
                    .join("/"),
                spaced_hex(result.frame.bytes())
            )),
        },
        output::contract::Format::Hex => {
            write_plain_line(format_args!("{}", result.frame.bytes_hex))
        }
        output::contract::Format::Ndjson => emit_stream(
            output::contract::Command::Read,
            sequence,
            result,
            Vec::new(),
        ),
        _ => unreachable!("read format is checked before command dispatch"),
    }
}
