// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::DissectFormat;

use packetcraftr_core::error::Kind;

pub(super) mod arguments;
mod rendering;

use std::time::SystemTime;

use packetcraftr_core as core;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::frame::LinkType;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{InputKind, read_bounded_file, read_stdin_bounded};
use crate::rendering::{emit_aggregate, emit_stderr_message, write_plain_line, write_raw};

impl super::Spec for Args {
    type Format = crate::output::contract::DissectFormat;
    const CANCELLATION: bool = false;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_projection_bytes: Bytes @ ResultRetention]);
        self.budget.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    arguments: Args,
    format: DissectFormat,
    stream: &crate::rendering::StreamEncoder,
) -> Result<(), CliError> {
    let registry = arguments.decode.registry()?;
    if arguments.fields.is_empty()
        && matches!(
            format,
            DissectFormat::Ndjson | DissectFormat::Csv | DissectFormat::Tsv
        )
    {
        return Err(super::projection::missing_fields_error());
    }
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
            Kind::Usage,
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
            .map_err(|source| CliError::caused(Kind::Usage, &source))?
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
        DissectFormat::Text => rendering::render_text(&decoded),
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
