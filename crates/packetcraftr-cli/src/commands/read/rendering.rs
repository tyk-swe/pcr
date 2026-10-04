// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Format;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{
    FieldTree, StreamEncoder, render_frame_text, render_frame_tree, write_hex_line,
};

pub(super) fn render_record(
    record: output::read::Frame,
    format: Format,
    stream: &StreamEncoder,
    tree: Option<&mut FieldTree>,
) -> Result<(), CliError> {
    let output::read::Frame {
        source_frame,
        frame,
        decoded,
    } = &record;
    match format {
        Format::Text => match tree {
            Some(tree) => render_frame_tree(*source_frame, frame, decoded.as_ref(), tree),
            None => render_frame_text(*source_frame, frame, decoded.as_ref()),
        },
        Format::Hex => write_hex_line(frame.bytes()),
        Format::Ndjson => Ok(stream.emit_data(output::read::Event::from(record), Vec::new())?),
        Format::Json | Format::Pcap | Format::PcapNg => Err(CliError::new(
            packetcraftr_core::error::Kind::Internal,
            "capture-file output returned before frame rendering",
        )),
        other => other.unreachable(),
    }
}
