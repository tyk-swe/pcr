// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Format;
use crate::output::envelope::Published;
use crate::output::frame::Record;

use crate::errors::CliError;
use crate::invocation::StreamEncoder;
use crate::packet_text::{FieldTree, Layers, render_frame};
use crate::publication::write_hex_line;

pub(super) fn render_record(
    invocation: &crate::invocation::Invocation,
    record: Record,
    format: Format,
    stream: &StreamEncoder,
    tree: Option<&mut FieldTree>,
) -> Result<(), CliError> {
    let Record {
        source_frame,
        frame,
        decoded,
    } = &record;
    match format {
        Format::Text => render_frame(
            invocation,
            *source_frame,
            frame,
            decoded.as_ref(),
            Layers::new(tree, stream.presentation()),
        ),
        Format::Hex => write_hex_line(frame.bytes()),
        Format::Ndjson => Ok(stream.emit_published(Published::new(
            super::output::Event::from(record),
            Vec::new(),
        ))?),
        Format::Json | Format::Pcap | Format::PcapNg => Err(CliError::new(
            packetcraftr_core::error::Kind::Internal,
            "capture-file output returned before frame rendering",
        )),
        other => other.unreachable(),
    }
}
