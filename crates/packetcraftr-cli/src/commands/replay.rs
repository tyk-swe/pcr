// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Replay CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;
mod selection;

use crate::output::contract::ExchangeFormat;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_netio as net;

use self::arguments::Args;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::FrameSelector;
use crate::input::{open_capture_file, validate_capture_stream_limits};
use crate::rendering::StreamEncoder;
use crate::system::InterfaceSelector;

use conversion::timing;

/// One validated replay: the source reader, the transmit providers, and the
/// bounds the run is held to.
struct ReplayRun {
    reader: Reader<std::fs::File>,
    options: packetcraftr::replay::Options,
    authorizer: packetcraftr::replay::SystemAuthorizer,
    transmitter: packetcraftr::replay::SystemTransmitter,
    clock: packetcraftr::clock::CancellableClock,
    selector: selection::Selector,
    requested_interface: Option<net::interface::Id>,
}

impl super::Spec for Args {
    type Format = crate::output::contract::ExchangeFormat;
    const CANCELLATION: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_millis(self.max_duration_ms))
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_duration_ms: Milliseconds @ Operation]);
        self.reader.resources(settings);
        self.policy.resources(settings);
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
    format: ExchangeFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    arguments.compression.validate(format.as_format())?;
    let mut prepared = prepare(&arguments)?;
    let filtered = prepared.selector.filter.is_some();
    let requested_interface = prepared.requested_interface.clone();
    let run = rendering::Run {
        reader: &mut prepared.reader,
        options: &prepared.options,
        selector: Some(&mut prepared.selector),
        authorizer: &mut prepared.authorizer,
        transmitter: &mut prepared.transmitter,
        clock: &mut prepared.clock,
    };
    match format {
        ExchangeFormat::Text => rendering::render_text(run, filtered),
        ExchangeFormat::Json => rendering::render_aggregate(run, requested_interface),
        ExchangeFormat::Ndjson => rendering::render_stream(run, stream),
        ExchangeFormat::Pcap => rendering::render_capture(
            run,
            rendering::CaptureSettings {
                format: capture::Format::Pcap,
                compression: arguments.compression,
            },
        ),
        ExchangeFormat::PcapNg => rendering::render_capture(
            run,
            rendering::CaptureSettings {
                format: capture::Format::PcapNg,
                compression: arguments.compression,
            },
        ),
    }
}

fn prepare(arguments: &Args) -> Result<ReplayRun, CliError> {
    let policy = arguments.policy.clone().into_policy();
    // Replay's aggregate ceilings come from the traffic policy rather than
    // from `--max-frames`/`--max-bytes`, but they bound the same capture
    // stream and are validated against the same cross-field rule.
    let capture_limits = OfflineCaptureLimitsArgs {
        max_frames: policy.max_packets_per_operation,
        max_bytes: policy.max_bytes_per_operation,
        reader: arguments.reader,
    };
    validate_capture_stream_limits(capture_limits)?;
    let timing = timing(arguments)?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let filter = FrameSelector::compile_optional(
        arguments.filter.as_deref(),
        &registry,
        arguments.reader.max_frame_bytes,
    )?;
    if arguments.interface_maps.len() + arguments.filter_maps.len() > 256 {
        return Err(CliError::new(
            core::error::Kind::Usage,
            "replay permits at most 256 interface rules",
        ));
    }
    let requested_interface = InterfaceSelector::parse_optional(arguments.interface.as_deref())?
        .map(InterfaceSelector::into_id);
    let mut rules = Vec::new();
    for mapping in &arguments.interface_maps {
        let (source, destination) = mapping.split_once('=').ok_or_else(|| {
            CliError::new(
                core::error::Kind::Usage,
                "--map-interface requires SOURCE_ID=OUTPUT_INTERFACE",
            )
        })?;
        let source = source.parse::<u32>().map_err(|_| {
            CliError::new(
                core::error::Kind::Usage,
                "source interface must be an unsigned capture-global ID",
            )
        })?;
        rules.push(selection::Rule {
            condition: selection::Match::Source(source),
            interface: InterfaceSelector::parse(destination)?.into_id(),
        });
    }
    for mapping in &arguments.filter_maps {
        let (expression, destination) = mapping.rsplit_once("=>").ok_or_else(|| {
            CliError::new(
                core::error::Kind::Usage,
                "--map-filter requires EXPR=>OUTPUT_INTERFACE",
            )
        })?;
        let condition = FrameSelector::compile_optional(
            Some(expression),
            &registry,
            arguments.reader.max_frame_bytes,
        )?
        .expect("explicit filter");
        rules.push(selection::Rule {
            condition: selection::Match::Filter(condition),
            interface: InterfaceSelector::parse(destination)?.into_id(),
        });
    }
    policy.validate().map_err(CliError::classified)?;
    let limits = packetcraftr::replay::Limits::from_policy(
        &policy,
        arguments.reader.max_frame_bytes,
        Duration::from_millis(arguments.max_duration_ms),
    );
    limits.validate().map_err(CliError::classified)?;
    let options = packetcraftr::replay::Options {
        interface: requested_interface.clone(),
        repeat: arguments.repeat,
        inter_pass_delay: Duration::from_millis(arguments.inter_pass_delay_ms),
        link_mode: arguments.link_mode.into(),
        timing,
        limits,
    };
    options.validate().map_err(CliError::classified)?;
    let mut input = open_capture_file(&arguments.path, arguments.reader)?;
    let reader = crate::input::snapshot_capture(
        &mut input,
        arguments.reader,
        capture::Limits {
            max_frames: limits.max_source_frames,
            max_bytes: arguments.reader.max_decoded_bytes,
        },
    )?;
    Ok(ReplayRun {
        reader,
        options,
        authorizer: packetcraftr::replay::SystemAuthorizer::new(
            Arc::clone(&registry),
            policy,
            arguments.allow_permissive_live,
        ),
        transmitter: packetcraftr::replay::SystemTransmitter::new(),
        clock: packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone()),
        selector: selection::Selector {
            filter,
            rules,
            fallback: requested_interface.is_some(),
        },
        requested_interface,
    })
}
