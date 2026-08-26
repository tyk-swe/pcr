// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output;

use crate::commands::format::FrameFormat;
use crate::errors::CliError;
use crate::rendering::{
    NdjsonStream, captured_frame_text, spaced_hex, write_plain_line, write_stdout_line,
};

pub(super) fn render_record(
    event: &output::read::Event,
    format: FrameFormat,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let output::read::Event::Frame {
        source_frame,
        frame,
        decoded,
    } = event
    else {
        unreachable!("read completion is rendered by the stream owner")
    };
    match format {
        FrameFormat::Text => match decoded {
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
        FrameFormat::Hex => write_plain_line(format_args!("{}", frame.bytes_hex())),
        FrameFormat::Ndjson => stream.emit_data(event, Vec::new()),
    }
}
