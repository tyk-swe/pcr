// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Replay CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;

use packetcraftr::output::contract::Format;

use std::fs::File;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    analysis::pcap::{self as capture, Reader},
    netio as net,
};

use self::arguments::Args;
use super::registry;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::FrameSelector;
use crate::input::{open_capture, validate_capture_stream_limits};
use crate::rendering::StreamEncoder;

use conversion::{interface, timing};

/// One validated replay: the source reader, the transmit providers, and the
/// bounds the run is held to.
struct ReplayRun {
    reader: Reader<File>,
    options: packetcraftr::replay::Options,
    authorizer: packetcraftr::replay::SystemAuthorizer,
    transmitter: packetcraftr::replay::SystemTransmitter,
    clock: packetcraftr::clock::SystemClock,
    filter: Option<FrameSelector>,
    requested_interface: net::interface::Id,
    max_interfaces: usize,
}

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let mut prepared = prepare(&arguments)?;
    let filtered = prepared.filter.is_some();
    let requested_interface = prepared.requested_interface.clone();
    let max_interfaces = prepared.max_interfaces;
    let run = rendering::Run {
        reader: &mut prepared.reader,
        options: &prepared.options,
        selector: prepared
            .filter
            .as_mut()
            .map(|selector| selector as &mut dyn packetcraftr::replay::Selector),
        authorizer: &mut prepared.authorizer,
        transmitter: &mut prepared.transmitter,
        clock: &mut prepared.clock,
    };
    match format {
        Format::Text => rendering::render_text(run, filtered),
        Format::Json => rendering::render_aggregate(run, requested_interface),
        Format::Ndjson => rendering::render_stream(run, stream),
        Format::Pcap => rendering::render_capture(
            run,
            rendering::CaptureSettings {
                format: capture::Format::Pcap,
                max_interfaces,
            },
        ),
        Format::PcapNg => rendering::render_capture(
            run,
            rendering::CaptureSettings {
                format: capture::Format::PcapNg,
                max_interfaces,
            },
        ),
        _ => unreachable!("command dispatch validated the output format"),
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
    let registry = registry()?;
    let filter = FrameSelector::compile_optional(
        arguments.filter.as_deref(),
        &registry,
        arguments.reader.max_frame_bytes,
    )?;
    let requested_interface = interface(&arguments.interface)?;
    policy.validate().map_err(CliError::classified)?;
    let limits = packetcraftr::replay::Limits::from_policy(
        &policy,
        arguments.reader.max_frame_bytes,
        Duration::from_millis(arguments.max_duration_ms),
    );
    limits.validate().map_err(CliError::classified)?;
    let reader = open_capture(&arguments.path, arguments.reader)?;
    Ok(ReplayRun {
        reader,
        options: packetcraftr::replay::Options {
            interface: requested_interface.clone(),
            link_mode: arguments.link_mode.into(),
            timing,
            limits,
        },
        authorizer: packetcraftr::replay::SystemAuthorizer::new(
            Arc::clone(&registry),
            policy,
            arguments.allow_permissive_live,
        ),
        transmitter: packetcraftr::replay::SystemTransmitter::new(),
        clock: packetcraftr::clock::SystemClock,
        filter,
        requested_interface,
        max_interfaces: arguments.reader.max_interfaces,
    })
}
