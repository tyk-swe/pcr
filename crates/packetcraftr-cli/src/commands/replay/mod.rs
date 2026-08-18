// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Replay CLI command logic.

pub(super) mod arguments;
mod conversion;
mod execution;
mod rendering;

use std::fs::File;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{analysis::pcap::Reader, netio as net, output};

use self::arguments::Args;
use super::registry;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities, FrameSelector};
use crate::input::{open_capture, validate_capture_stream_limits};

use conversion::{interface, timing};
use execution::FilterSelector;

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

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let mut prepared = prepare(&arguments)?;
    let filtered = prepared.filter.is_some();
    let mut filter = prepared
        .filter
        .as_ref()
        .map(|selector| FilterSelector { selector });
    let selector = filter
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
            prepared.requested_interface,
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
    let filter = prepare_filter(
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
            arguments.confirm_live_opt_in,
        ),
        transmitter: packetcraftr::replay::SystemTransmitter::new(),
        clock: packetcraftr::clock::SystemClock,
        filter,
        requested_interface,
        max_interfaces: arguments.max_interfaces,
    })
}

fn prepare_filter(
    source: Option<&str>,
    registry: &Arc<packetcraftr::core::registry::Registry>,
    max_frame_bytes: usize,
) -> Result<Option<FrameSelector>, CliError> {
    source
        .map(|source| {
            let filter = filtering::compile(source, registry, Capabilities::frames_only())?;
            Ok(FrameSelector::new(
                Arc::clone(registry),
                filter,
                max_frame_bytes,
            ))
        })
        .transpose()
}

pub(crate) fn classified_error(error: packetcraftr::replay::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
