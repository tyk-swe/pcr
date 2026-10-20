// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core as core;
use packetcraftr_core::error::Kind;

use crate::errors::CliError;
use crate::output::{self, contract::Format};
use crate::rendering::{
    emit_published, render_diagnostics_text, spaced_hex, write_hex_line, write_raw,
    write_stdout_line, write_summary_line,
};

pub(super) fn render_packet(
    invocation: &crate::invocation::Invocation,
    built: core::build::BuiltPacket,
    format: Format,
    presentation: crate::rendering::Presentation,
) -> Result<(), CliError> {
    match format {
        Format::Text => {
            write_summary_line(
                invocation,
                format_args!("built {} bytes", built.bytes.len()),
            )?;
            write_stdout_line(invocation, format_args!("{}", spaced_hex(&built.bytes)))?;
            presentation.details(
                invocation,
                "Packet fields",
                &core::document::Packet::from_packet(&built.packet),
            )?;
            presentation.details(invocation, "Packet layout", &built.layout)?;
            render_diagnostics_text(invocation, &built.diagnostics)
        }
        Format::Hex => write_hex_line(&built.bytes),
        Format::Raw => write_raw(&built.bytes),
        Format::Json => emit_published(
            invocation,
            output::contract::Command::Build,
            output::envelope::Published::<output::build::Report>::from(built),
        ),
        Format::Csv | Format::Ndjson | Format::Pcap | Format::PcapNg => Err(CliError::new(
            Kind::Internal,
            "streaming and capture build output returned before packet rendering",
        )),
    }
}
