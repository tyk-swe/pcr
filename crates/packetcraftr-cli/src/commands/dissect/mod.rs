// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr::{
    core::{
        self,
        frame::{Frame, LinkType},
    },
    output,
};

use self::arguments::Args;
use super::super::errors::CliError;
use super::super::filtering::{self, Capabilities};
use super::super::input::{InputKind, read_bounded_file, read_stdin_bounded};
use super::super::rendering::{
    emit_aggregate, render_diagnostics_text, write_plain_line, write_raw, write_stdout_line,
};
use super::format::DissectFormat;
use super::registry_with_tls_ports;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = DissectFormat::narrow(output::contract::Command::Dissect, format)?;
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
            .map_err(|source| CliError::new(2, source.to_string()))?
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
    let decoded = core::decode::Dissector::new(Arc::clone(&registry))
        .decode(
            Frame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
                .map_err(|source| CliError::new(3, source.to_string()))?,
            core::decode::Options::default(),
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    // The filter selects emission, not validity: a frame it rejects is still
    // decoded successfully, while an unsupported output format is refused
    // whether or not the frame matched.
    let kept = match &filter {
        Some(filter) => filter
            .matches(&core::filter::Context {
                decoded: &decoded,
                number: 1,
                tcp_stream: None,
                udp_stream: None,
            })
            .map_err(|source| CliError::new(3, source.to_string()))?,
        None => true,
    };
    if format == DissectFormat::Document {
        if !kept {
            return Ok(());
        }
        let (doc, _) =
            core::document::v2::Document::from_decoded(&decoded, &registry, arguments.full);
        let yaml = doc
            .to_yaml_string()
            .map_err(|source| CliError::new(2, source.to_string()))?;
        write_plain_line(format_args!("{}", yaml.trim_end()))?;
        return render_diagnostics_text(&decoded.diagnostics);
    }
    let (result, diagnostics) = output::dissect::Result::from_decoded(decoded);
    match format {
        DissectFormat::Text => {
            if !kept {
                return Ok(());
            }
            write_stdout_line(format_args!(
                "decoded {} bytes into {} layer(s)",
                result.length,
                result.packet.layers.len()
            ))?;
            for (index, layer) in result.packet.layers.iter().enumerate() {
                write_stdout_line(format_args!("{index}: {}", layer.protocol))?;
            }
            render_diagnostics_text(&diagnostics)
        }
        DissectFormat::Hex => {
            if !kept {
                return Ok(());
            }
            write_plain_line(format_args!("{}", result.bytes_hex))
        }
        DissectFormat::Raw => {
            if !kept {
                return Ok(());
            }
            write_raw(result.bytes())
        }
        DissectFormat::Json => emit_aggregate(
            output::contract::Command::Dissect,
            output::dissect::AggregateResult::from_filter(kept, result),
            diagnostics,
        ),
        DissectFormat::Document => unreachable!(),
    }
}
