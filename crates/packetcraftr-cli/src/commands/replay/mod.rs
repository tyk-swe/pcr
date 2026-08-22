// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Replay CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;

use std::fs::File;
use std::time::Duration;

use packetcraftr::{analysis::pcap::Reader, netio as net, output};

use self::arguments::Args;
use super::registry;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::FrameSelector;
use crate::input::{open_capture, validate_capture_stream_limits};
use crate::rendering::NdjsonStream;

use conversion::{interface, timing};

struct Prepared {
    reader: Reader<File>,
    options: packetcraftr::replay::Options,
    authorizer: packetcraftr::replay::SystemAuthorizer,
    transmitter: packetcraftr::replay::SystemTransmitter,
    clock: packetcraftr::clock::SystemClock,
    filter: Option<FrameSelector>,
    requested_interface: net::interface::Id,
    max_interfaces: usize,
}

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let mut prepared = prepare(&arguments)?;
    let filtered = prepared.filter.is_some();
    let selector = prepared
        .filter
        .as_mut()
        .map(|selector| selector as &mut dyn packetcraftr::replay::Selector);
    match format {
        output::contract::Format::Text => rendering::render_text(
            &mut prepared.reader,
            &prepared.options,
            selector,
            &mut prepared.authorizer,
            &mut prepared.transmitter,
            &mut prepared.clock,
            filtered,
        ),
        output::contract::Format::Json => rendering::render_aggregate(
            &mut prepared.reader,
            &prepared.options,
            selector,
            &mut prepared.authorizer,
            &mut prepared.transmitter,
            &mut prepared.clock,
            prepared.requested_interface,
        ),
        output::contract::Format::Ndjson => rendering::render_stream(
            &mut prepared.reader,
            &prepared.options,
            selector,
            &mut prepared.authorizer,
            &mut prepared.transmitter,
            &mut prepared.clock,
            stream,
        ),
        output::contract::Format::Pcap | output::contract::Format::PcapNg => {
            rendering::render_capture(
                &mut prepared.reader,
                &prepared.options,
                selector,
                &mut prepared.authorizer,
                &mut prepared.transmitter,
                &mut prepared.clock,
                rendering::CaptureSettings {
                    format,
                    max_interfaces: prepared.max_interfaces,
                },
            )
        }
        _ => unreachable!("replay format is checked before command dispatch"),
    }
}

fn prepare(arguments: &Args) -> Result<Prepared, CliError> {
    let policy = arguments.policy.clone().into_policy();
    validate_capture_stream_limits(
        policy.max_packets_per_operation,
        policy.max_bytes_per_operation,
        arguments.max_frame_bytes,
        arguments.max_interfaces,
    )?;
    let timing = timing(arguments)?;
    let registry = registry()?;
    let filter = FrameSelector::compile_optional(
        arguments.filter.as_deref(),
        &registry,
        arguments.max_frame_bytes,
    )?;
    let requested_interface = interface(&arguments.interface)?;
    policy.validate().map_err(CliError::classified)?;
    let limits = packetcraftr::replay::Limits {
        max_frames: policy.max_packets_per_operation,
        max_bytes: policy.max_bytes_per_operation,
        max_frame_bytes: arguments.max_frame_bytes,
        max_duration: Duration::from_millis(arguments.max_duration_ms),
    }
    .validate()
    .map_err(CliError::classified)?;
    let reader = open_capture(
        &arguments.path,
        OfflineCaptureLimitsArgs {
            max_frames: policy.max_packets_per_operation,
            max_bytes: policy.max_bytes_per_operation,
            max_frame_bytes: arguments.max_frame_bytes,
            max_interfaces: arguments.max_interfaces,
        },
    )?;
    Ok(Prepared {
        reader,
        options: packetcraftr::replay::Options {
            interface: requested_interface.clone(),
            link_mode: arguments.link_mode.into(),
            timing,
            limits,
        },
        authorizer: packetcraftr::replay::SystemAuthorizer::new(
            policy,
            arguments.allow_malformed_live,
        ),
        transmitter: packetcraftr::replay::SystemTransmitter::new(),
        clock: packetcraftr::clock::SystemClock,
        filter,
        requested_interface,
        max_interfaces: arguments.max_interfaces,
    })
}
