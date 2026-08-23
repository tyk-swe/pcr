// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
use super::super::error::{INPUT_READ, failure};
use super::super::filtering::{self, Capabilities};
use super::super::input::{InputKind, read_bounded_file, read_stdin_bounded};
use super::super::rendering::{
    emit_aggregate, render_diagnostics_text, write_plain_line, write_raw, write_stdout_line,
};
use super::registry;
use packetcraftr::BoundaryError;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), BoundaryError> {
    let registry = registry()?;
    // A bad filter fails before any input is read, so it cannot leave the
    // command waiting on standard input for frame bytes it would never use.
    let filter = arguments
        .filter
        .as_deref()
        .map(|source| filtering::compile(source, &registry, Capabilities::frames_only()))
        .transpose()?;
    let bytes = match (arguments.hex, arguments.file) {
        (Some(value), None) => core::protocol::raw::parse_hex(&value)
            .map_err(|source| failure(INPUT_READ, source.to_string()))?
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
                .map_err(BoundaryError::from_error)?,
            core::decode::Options::default(),
        )
        .map_err(BoundaryError::from_error)?;
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
            .map_err(BoundaryError::from_error)?,
        None => true,
    };
    let (result, diagnostics) = output::dissect::Result::from_decoded(decoded);
    match format {
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
        output::contract::Format::Json => emit_aggregate(
            output::contract::Command::Dissect,
            output::dissect::AggregateResult::from_filter(kept, result),
            diagnostics,
        ),
        _ => unreachable!("dissect format is checked before command dispatch"),
    }
}
