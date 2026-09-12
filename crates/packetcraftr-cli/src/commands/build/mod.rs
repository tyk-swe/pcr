// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr_cli::output::contract::Format;

use packetcraftr_cli::output;
use packetcraftr_core as core;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Classified as _;
use packetcraftr_core::error::Kind;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::{
    StreamEncoder, emit_aggregate, render_diagnostics_text, spaced_hex, write_plain_line,
    write_raw, write_stdout_line, write_summary_line,
};

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let maximum = arguments.template.max_template_packets;
    let axes = arguments.template.parse()?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    // Recipe byte limits bound parsing; the builder owns the requested layer budget.
    let packet = read_recipe(arguments.recipe, &registry, usize::MAX)?;
    // Keep OS signal termination while recipe input can block waiting for EOF.
    crate::cancellation::install()?;
    let template = axes.into_template(packet);
    let packets = template.expand(maximum).map_err(CliError::classified)?;
    if packets.len() != 1 && matches!(format, Format::Json | Format::Raw) {
        return Err(CliError::new(
            Kind::Cli,
            "JSON and raw build output require exactly one packet; use text, hex, or NDJSON for packet sets",
        ));
    }
    let builder = core::build::Builder::new(registry);
    let mut summary = output::build::Complete::default();
    for packet in packets {
        crate::cancellation::check()?;
        let built = builder
            .build(
                packet.map_err(CliError::classified)?,
                core::codec::Context::default(),
                arguments.budget.build_options(arguments.mode.into()),
            )
            .map_err(build_error)?;
        crate::cancellation::check()?;
        let bytes = u64::try_from(built.bytes.len())
            .map_err(|_| CliError::new(Kind::Internal, "built byte count overflowed"))?;
        summary.bytes_built = summary
            .bytes_built
            .checked_add(bytes)
            .ok_or_else(|| CliError::new(Kind::Internal, "built byte count overflowed"))?;
        if format == Format::Ndjson {
            let (packet, diagnostics) = output::build::Report::from_built(built);
            stream.emit_data(
                output::build::PacketEvent {
                    packet_index: summary.packets_built,
                    packet,
                },
                diagnostics,
            )?;
        } else {
            render_packet(built, format)?;
        }
        summary.packets_built = super::increment_counter(summary.packets_built, "built packets")?;
    }
    // Startup handles cancellation after JSON publication without appending
    // a second aggregate document to stdout.
    if format != Format::Json {
        crate::cancellation::check()?;
    }
    if format == Format::Ndjson {
        stream.complete(summary, Vec::new())?;
    }
    Ok(())
}

fn render_packet(built: core::build::BuiltPacket, format: Format) -> Result<(), CliError> {
    match format {
        Format::Text => {
            write_summary_line(format_args!("built {} bytes", built.bytes.len()))?;
            write_stdout_line(format_args!("{}", spaced_hex(&built.bytes)))?;
            render_diagnostics_text(&built.diagnostics)
        }
        Format::Hex => write_plain_line(format_args!("{}", output::hex::CompactHex(&built.bytes))),
        Format::Raw => write_raw(&built.bytes),
        Format::Json => {
            let (result, diagnostics) = output::build::Report::from_built(built);
            emit_aggregate(output::contract::Command::Build, result, diagnostics)
        }
        _ => unreachable!("command dispatch validated the output format"),
    }
}

fn build_error(error: core::build::Error) -> CliError {
    match error {
        error @ (core::build::Error::LayerLimit { .. }
        | core::build::Error::PacketSizeLimit { .. }) => {
            let classification = error.classification();
            CliError::from_classification(
                Classification::new(
                    "packet.build_resource_limit",
                    Kind::Packet,
                    classification.remediation,
                ),
                error.to_string(),
                error.causes(),
            )
        }
        error => CliError::classified(error),
    }
}
