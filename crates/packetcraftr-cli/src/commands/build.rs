// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod capture_output;
mod rendering;

use crate::output::contract::BuildFormat;

use crate::output;
use packetcraftr_core as core;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Classified as _;
use packetcraftr_core::error::Kind;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::{StreamEncoder, render_diagnostics_stderr, stream_capture_error};

impl super::Spec for Args {
    type Format = crate::output::contract::BuildFormat;
    const CANCELLATION: bool = false;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.template.resources(settings);
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
    format: BuildFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let capture = arguments.capture.resolve(format.as_format())?;
    let maximum = arguments.template.max_template_packets;
    let axes = arguments.template.parse()?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    // Recipe byte limits bound parsing; the builder owns the requested layer budget.
    let packet = read_recipe(arguments.recipe, &registry, usize::MAX)?;
    if let Some(capture) = &capture {
        capture.validate_root(&packet)?;
    }
    // Keep OS signal termination while recipe input can block waiting for EOF.
    crate::cancellation::install()?;
    let template = axes.into_template(packet);
    let packets = template.expand(maximum).map_err(CliError::classified)?;
    if packets.len() != 1 && matches!(format, BuildFormat::Json | BuildFormat::Raw) {
        return Err(CliError::new(
            Kind::Usage,
            "JSON and raw build output require exactly one packet; use text, hex, or NDJSON for packet sets",
        ));
    }
    let builder = core::build::Builder::new(registry);
    let mut writer = capture
        .as_ref()
        .map(capture_output::CaptureOutput::writer)
        .transpose()?;
    let mut summary = output::build::Complete::default();
    let mut diagnostics = Vec::new();
    let result = (|| {
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
            if let (Some(writer), Some(capture)) = (writer.as_mut(), capture.as_ref()) {
                capture.validate_wire(&built)?;
                // One template expansion repeats the same builder diagnostic per
                // packet; collapse by code so the stderr summary stays bounded.
                for diagnostic in built.diagnostics {
                    core::diagnostic::push_once(&mut diagnostics, diagnostic);
                }
                let frame =
                    core::frame::Frame::new(capture.timestamp, capture.link_type, built.bytes)
                        .map_err(CliError::classified)?;
                writer.write_frame(&frame).map_err(|source| {
                    stream_capture_error("write capture output failed", source)
                })?;
            } else if format == BuildFormat::Ndjson {
                stream.emit_published(
                    output::envelope::Published::<output::build::PacketEvent>::from((
                        summary.packets_built,
                        built,
                    )),
                )?;
            } else {
                rendering::render_packet(built, format)?;
            }
            summary.packets_built =
                super::increment_counter(summary.packets_built, "built packets")?;
        }
        Ok::<(), CliError>(())
    })();
    // Finish initialized compression even when a later packet fails, keeping
    // every frame already written readable. Preserve the original failure if
    // finalization also fails; finish flushes the underlying destination.
    let finished = writer
        .map(|writer| writer.into_inner().finish().map_err(CliError::classified))
        .transpose();
    match (result, finished) {
        (Err(primary), Err(secondary)) => {
            return Err(primary.with_secondary("output finalization", secondary));
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
        (Ok(()), Ok(_)) => {}
    }
    if capture.is_some() {
        render_diagnostics_stderr(&diagnostics)?;
    }
    // Startup handles cancellation after JSON publication without appending
    // a second aggregate document to stdout.
    if format != BuildFormat::Json {
        crate::cancellation::check()?;
    }
    if format == BuildFormat::Ndjson {
        stream.complete(summary, Vec::new())?;
    }
    Ok(())
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
