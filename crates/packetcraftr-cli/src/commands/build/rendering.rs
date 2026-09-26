// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `build`'s per-packet text, hex, raw, and JSON output.

use packetcraftr_core as core;
use packetcraftr_core::error::Kind;

use crate::errors::CliError;
use crate::output::{self, contract::BuildFormat};
use crate::rendering::{
    emit_aggregate, render_diagnostics_text, spaced_hex, write_hex_line, write_raw,
    write_stdout_line, write_summary_line,
};

pub(super) fn render_packet(
    built: core::build::BuiltPacket,
    format: BuildFormat,
) -> Result<(), CliError> {
    match format {
        BuildFormat::Text => {
            write_summary_line(format_args!("built {} bytes", built.bytes.len()))?;
            write_stdout_line(format_args!("{}", spaced_hex(&built.bytes)))?;
            render_diagnostics_text(&built.diagnostics)
        }
        BuildFormat::Hex => write_hex_line(&built.bytes),
        BuildFormat::Raw => write_raw(&built.bytes),
        BuildFormat::Json => {
            let (result, diagnostics) = output::build::Report::from_built(built);
            emit_aggregate(output::contract::Command::Build, result, diagnostics)
        }
        BuildFormat::Ndjson | BuildFormat::Pcap | BuildFormat::PcapNg => Err(CliError::new(
            Kind::Internal,
            "streaming and capture build output returned before packet rendering",
        )),
    }
}
