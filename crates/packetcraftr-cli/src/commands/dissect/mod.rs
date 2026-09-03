// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

pub(super) mod arguments;

use std::time::SystemTime;

use packetcraftr::{
    core::{
        self,
        frame::{Frame, LinkType},
    },
    output,
};

use self::arguments::Args;
use super::format::BuildFormat;
use super::registry_with_tls_ports;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{InputKind, read_bounded_file, read_stdin_bounded};
use crate::rendering::{
    emit_aggregate, emit_stderr_message, render_diagnostics_text, write_plain_line, write_raw,
    write_stdout_line, write_summary_line,
};

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = BuildFormat::narrow(output::contract::Command::Dissect, format)?;
    let registry = registry_with_tls_ports(&arguments.tls_ports.ports)?;
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
        (None, Some(path)) => read_bounded_file(
            &path,
            core::document::DEFAULT_MAX_DOCUMENT_BYTES,
            InputKind::Frame,
        )?,
        (None, None) => {
            read_stdin_bounded(core::document::DEFAULT_MAX_DOCUMENT_BYTES, InputKind::Frame)?
        }
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let decoded = core::decode::Dissector::new(registry)
        .decode(
            Frame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
                .map_err(CliError::classified)?,
            core::decode::Options::default(),
        )
        .map_err(CliError::classified)?;
    // The filter selects emission, not validity: a frame it rejects is still
    // decoded successfully, while an unsupported output format is refused
    // whether or not the frame matched.
    let kept = match &filter {
        Some(filter) => filter
            .matches(&core::filter::Context {
                decoded: &decoded,
                derived: &[],
                number: 1,
                tcp_stream: None,
                udp_stream: None,
            })
            .map_err(|source| CliError::new(Kind::Packet, source.to_string()))?,
        None => true,
    };
    let (result, diagnostics) = output::dissect::Report::from_decoded(decoded);
    // An unmatched frame keeps byte-oriented stdout empty on success; the
    // notice goes to stderr through the shared human renderer.
    if !kept && !matches!(format, BuildFormat::Json) {
        return emit_stderr_message("frame did not match the filter");
    }
    match format {
        BuildFormat::Text => {
            write_summary_line(format_args!(
                "decoded {} bytes into {} layer(s)",
                result.frame.length,
                result.packet.layers.len()
            ))?;
            for (index, layer) in result.packet.layers.iter().enumerate() {
                write_stdout_line(format_args!("{index}: {}", layer.protocol))?;
            }
            render_diagnostics_text(&diagnostics)
        }
        BuildFormat::Hex => write_plain_line(format_args!("{}", result.frame.bytes_hex())),
        BuildFormat::Raw => write_raw(result.frame.bytes()),
        BuildFormat::Json => emit_aggregate(
            output::contract::Command::Dissect,
            output::dissect::AggregateResult::new(kept.then_some(result)),
            diagnostics,
        ),
    }
}
