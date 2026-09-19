// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output::contract::DissectFormat;

use packetcraftr_core::error::Kind;

pub(super) mod arguments;

use std::time::SystemTime;

use packetcraftr_core as core;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::frame::LinkType;

use packetcraftr_cli::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{InputKind, read_bounded_file, read_stdin_bounded};
use crate::rendering::{
    emit_aggregate, emit_stderr_message, render_diagnostics_text, render_dns_records,
    write_plain_line, write_raw, write_stdout_line, write_summary_line,
};

pub(super) fn run(
    arguments: Args,
    format: DissectFormat,
    stream: &crate::rendering::StreamEncoder,
) -> Result<(), CliError> {
    let registry = arguments.decode.registry()?;
    let projector = super::projection::Projector::prepare(
        &arguments.fields,
        arguments.max_projection_bytes,
        &registry,
        output::contract::Command::Dissect,
        format.as_format(),
    )?;
    if projector
        .as_ref()
        .is_some_and(|projector| projector.projection.requirements().stream_index)
    {
        return Err(CliError::new(
            Kind::Cli,
            "dissect cannot assign stream indexes; use read with --field",
        ));
    }
    let max_packet_size = arguments.budget.max_packet_size;
    // A bad filter fails before any input is read, so it cannot leave the
    // command waiting on standard input for frame bytes it would never use.
    let filter = arguments
        .filter
        .as_deref()
        .map(|source| filtering::compile(source, &registry, Capabilities::frames_only()))
        .transpose()?;
    let bytes = match (arguments.hex, arguments.file) {
        (Some(value), None) => core::protocol::raw::parse_hex(&value)
            .map_err(|source| CliError::new(Kind::Cli, source.to_string()))?
            .to_vec(),
        (None, Some(path)) => read_bounded_file(&path, max_packet_size, InputKind::Frame)?,
        (None, None) => read_stdin_bounded(max_packet_size, InputKind::Frame)?,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let decoded = core::decode::Dissector::new(registry)
        .decode(
            Frame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
                .map_err(CliError::classified)?,
            arguments.budget.decode_options(),
        )
        .map_err(CliError::classified)?;
    // The filter selects emission, not validity: a frame it rejects is still
    // decoded successfully, while an unsupported output format is refused
    // whether or not the frame matched.
    let kept = match &filter {
        Some(filter) => filtering::matches_decoded(
            filter,
            &core::filter::Context {
                decoded: &decoded,
                derived: &[],
                number: 1,
                tcp_stream: None,
                udp_stream: None,
            },
        )?,
        None => true,
    };
    if let Some(mut projector) = projector {
        if kept {
            let values = projector
                .projection
                .values(
                    &core::filter::Context {
                        decoded: &decoded,
                        derived: &[],
                        number: 1,
                        tcp_stream: None,
                        udp_stream: None,
                    },
                    projector.remaining(),
                )
                .map_err(CliError::classified)?;
            projector.emit(1, values, stream)?;
        }
        return projector.finish(1, u64::from(decoded.frame.captured_length()), stream);
    }
    // An unmatched frame keeps byte-oriented stdout empty on success; the
    // notice goes to stderr through the shared human renderer.
    if !kept && !matches!(format, DissectFormat::Json) {
        return emit_stderr_message("frame did not match the filter");
    }
    match format {
        DissectFormat::Text => {
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
        DissectFormat::Hex => write_plain_line(format_args!(
            "{}",
            output::hex::CompactHex(&decoded.original)
        )),
        DissectFormat::Raw => write_raw(&decoded.original),
        DissectFormat::Json => {
            let (dissection, diagnostics) = if kept {
                let (result, diagnostics) = output::dissect::Report::from_decoded(decoded);
                (Some(result), diagnostics)
            } else {
                (None, decoded.diagnostics)
            };
            emit_aggregate(
                output::contract::Command::Dissect,
                output::dissect::AggregateResult::new(dissection),
                diagnostics,
            )
        }
        DissectFormat::Ndjson | DissectFormat::Csv | DissectFormat::Tsv => Err(CliError::new(
            Kind::Internal,
            "--field output returned before dissection rendering",
        )),
    }
}
