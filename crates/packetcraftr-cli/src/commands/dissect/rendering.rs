// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `dissect`'s text output.

use packetcraftr_core::decode::DecodedPacket;

use crate::errors::CliError;
use crate::rendering::{
    render_diagnostics_text, render_dns_records, write_stdout_line, write_summary_line,
};

/// The decoded frame's size, one line per layer, its DNS records, and its
/// diagnostics.
pub(super) fn render_text(decoded: &DecodedPacket) -> Result<(), CliError> {
    write_summary_line(format_args!(
        "decoded {} bytes into {} layer(s)",
        decoded.original.len(),
        decoded.packet.len()
    ))?;
    for (index, layer) in decoded.packet.iter().enumerate() {
        write_stdout_line(format_args!("{index}: {}", layer.protocol_id()))?;
    }
    render_dns_records(&packetcraftr_core::document::Packet::from_packet(
        &decoded.packet,
    ))?;
    render_diagnostics_text(&decoded.diagnostics)
}
