// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::decode::DecodedPacket;

use crate::errors::CliError;
use crate::rendering::{
    FieldTree, render_diagnostics_text, render_dns_records, write_stdout_line, write_summary_line,
};

pub(super) fn render_text(
    decoded: &DecodedPacket,
    tree: Option<&mut FieldTree>,
) -> Result<(), CliError> {
    write_summary_line(format_args!(
        "decoded {} bytes into {} layer(s)",
        decoded.frame.bytes().len(),
        decoded.packet.len()
    ))?;
    let packet = packetcraftr_core::document::Packet::from_packet(&decoded.packet);
    match tree {
        Some(tree) => {
            tree.render_layers(&packet, |index, protocol| format!("{index}: {protocol}"))?;
        }
        None => {
            for (index, layer) in decoded.packet.iter().enumerate() {
                write_stdout_line(format_args!("{index}: {}", layer.protocol_id()))?;
            }
            render_dns_records(&packet)?;
        }
    }
    render_diagnostics_text(&decoded.diagnostics)
}
