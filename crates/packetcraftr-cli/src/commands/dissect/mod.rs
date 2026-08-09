// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use std::time::SystemTime;

use packetcraftr::{
    output, packet,
    packet::frame::{Frame, LinkType},
};

use self::arguments::DissectArgs;
use super::super::errors::CliError;
use super::super::filtering::{self, Capabilities};
use super::super::input::{read_bounded_file, read_stdin_bounded};
use super::super::rendering::{
    emit_json, render_diagnostics_text, write_plain_line, write_raw, write_stdout_line,
};
use super::super::system::default_registry_arc;

pub(super) fn run(
    arguments: DissectArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    // A bad filter fails before any input is read, so it cannot leave the
    // command waiting on standard input for frame bytes it would never use.
    let filter = match arguments.filter.as_deref() {
        Some(source) => Some(filtering::compile(
            source,
            &registry,
            Capabilities::frames_only(),
        )?),
        None => None,
    };
    let bytes = match (arguments.hex, arguments.file) {
        (Some(value), None) => packet::expression::decode_hex(&value)
            .map_err(|source| CliError::new(2, source.to_string()))?
            .to_vec(),
        (None, Some(path)) => {
            read_bounded_file(&path, packet::document::DEFAULT_MAX_DOCUMENT_BYTES)?
        }
        (None, None) => read_stdin_bounded(packet::document::DEFAULT_MAX_DOCUMENT_BYTES)?,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let decoded = packet::decode::Decoder::new(registry)
        .decode(
            Frame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
                .map_err(|source| CliError::new(3, source.to_string()))?,
            packet::decode::Options::default(),
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    // The filter selects emission, not validity: a frame it rejects emits
    // nothing and the command still succeeds, while an unsupported output
    // format is refused whether or not the frame matched.
    let kept = match &filter {
        Some(filter) => filter
            .matches(&packet::filter::Context {
                decoded: &decoded,
                number: 1,
                tcp_stream: None,
                udp_stream: None,
            })
            .map_err(|source| CliError::new(3, source.to_string()))?,
        None => true,
    };
    let (result, diagnostics) = output::dissect::Result::from_decoded(decoded);
    match output {
        output::contract::Format::Text => {
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
        output::contract::Format::Hex => {
            if !kept {
                return Ok(());
            }
            write_plain_line(format_args!("{}", result.bytes_hex))
        }
        output::contract::Format::Raw => {
            if !kept {
                return Ok(());
            }
            write_raw(result.bytes())
        }
        output::contract::Format::Json => {
            if !kept {
                return Ok(());
            }
            emit_json(&output::envelope::Aggregate::success(
                output::contract::Command::Dissect,
                result,
                diagnostics,
            ))
        }
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Dissect,
                format: output,
            },
        )),
    }
}
