// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod capture_output;
mod rendering;
mod session;

use std::sync::Arc;
use std::time::Duration;

use crate::output::contract::BuildFormat;

use crate::output;
use packetcraftr_core as core;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Classified as _;
use packetcraftr_core::error::Kind;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::{apply_overrides, read_recipe};
use crate::rendering::{
    StreamEncoder, render_diagnostics_stderr, stream_capture_error, stream_limits,
};

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
    let session =
        arguments
            .session
            .resolve(&registry, arguments.budget, arguments.mode.into(), maximum)?;
    if session.as_ref().is_some_and(|session| session.step_chosen) && capture.is_none() {
        return Err(CliError::new(
            Kind::Usage,
            "--session-step-ns requires PCAP or PCAPNG output",
        ));
    }
    // Enforce the layer budget before allocating the complete recipe.
    let mut packet = read_recipe(arguments.recipe, &registry, arguments.budget.max_layers)?;
    apply_overrides(&mut packet, &registry, &arguments.set)?;
    if let Some(capture) = &capture {
        capture.validate_root(&packet)?;
    }
    // Keep OS signal termination while recipe input can block waiting for EOF.
    crate::cancellation::install()?;
    let builder = core::build::Builder::new(Arc::clone(&registry));
    let build_options = arguments.budget.build_options(arguments.mode.into());
    let step = session
        .as_ref()
        .map_or(Duration::ZERO, |session| session.step);
    let limits = stream_limits(
        maximum as u64,
        (maximum as u64).saturating_mul(arguments.budget.max_packet_size as u64),
    );
    let template;
    let packets: Box<dyn ExactSizeIterator<Item = Result<core::packet::Packet, CliError>> + '_> =
        match &session {
            Some(session) => {
                let frames = session.expand(&packet)?;
                // A generated conversation is checked whole, so a frame that cannot
                // build, encode, or fit the capture format fails before the first
                // byte of output.
                let mut dry_run = capture
                    .as_ref()
                    .map(|capture| capture.dry_run_writer(limits))
                    .transpose()?;
                for (ordinal, frame) in frames.iter().enumerate() {
                    crate::cancellation::check()?;
                    let built = builder
                        .build(
                            frame.clone(),
                            core::codec::Context::default(),
                            build_options.clone(),
                        )
                        .map_err(build_error)?;
                    if let (Some(writer), Some(capture)) = (dry_run.as_mut(), capture.as_ref()) {
                        capture.validate_wire(&built)?;
                        let timestamp =
                            session::frame_timestamp(capture.timestamp, step, ordinal as u64)?;
                        let frame =
                            core::frame::Frame::new(timestamp, capture.link_type, built.bytes)
                                .map_err(CliError::classified)?;
                        writer.write_frame(&frame).map_err(|source| {
                            stream_capture_error("write capture output failed", source)
                        })?;
                    }
                }
                Box::new(frames.into_iter().map(Ok))
            }
            None => {
                template = axes.into_template(packet, &registry)?;
                Box::new(
                    template
                        .expand(maximum)
                        .map_err(CliError::classified)?
                        .map(|packet| packet.map_err(CliError::classified)),
                )
            }
        };
    if packets.len() != 1 && matches!(format, BuildFormat::Json | BuildFormat::Raw) {
        return Err(CliError::new(
            Kind::Usage,
            "JSON and raw build output require exactly one packet; use text, hex, or NDJSON for packet sets",
        ));
    }
    let mut writer = capture
        .as_ref()
        .map(|capture| capture.writer(limits))
        .transpose()?;
    let mut summary = output::build::Complete::default();
    let mut diagnostics = Vec::new();
    let result = (|| {
        for packet in packets {
            crate::cancellation::check()?;
            let built = builder
                .build(
                    packet?,
                    core::codec::Context::default(),
                    build_options.clone(),
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
                // Collapse by code so the stderr summary stays bounded.
                for diagnostic in built.diagnostics {
                    core::diagnostic::push_once(&mut diagnostics, diagnostic);
                }
                let timestamp =
                    session::frame_timestamp(capture.timestamp, step, summary.packets_built)?;
                let frame = core::frame::Frame::new(timestamp, capture.link_type, built.bytes)
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
    // Finish initialized compression even when a later packet fails.
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
    // Startup handles cancellation after JSON publication without a second document.
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
