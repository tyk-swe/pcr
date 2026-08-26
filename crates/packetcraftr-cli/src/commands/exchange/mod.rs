// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, output};

use self::arguments::Args;
use super::super::errors::CliError;
use super::super::system::{client, prepare_route};
use super::format::{CollectedFormat, ExchangeFormat};
use super::registry;
use crate::command_options::SendArgs;
use crate::rendering::StreamEncoder;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    let format = ExchangeFormat::narrow(output::contract::Command::Exchange, format)?;
    let Args {
        send,
        timeout_ms,
        max_responses,
        max_unmatched_frames,
        limits,
    } = arguments;
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
        policy,
    } = send;
    let limits = limits.into_limits();
    let mut options = packetcraftr::exchange::Options {
        timeout: Duration::from_millis(timeout_ms),
        max_template_packets: 1,
        max_responses,
        max_unmatched_frames,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        ..packetcraftr::exchange::Options::default()
    };
    options.decode.max_packet_size = limits.snap_length;
    // Validate before packet parsing can trigger hostname/interface work.
    options.validate().map_err(CliError::classified)?;

    let registry = registry()?;
    let request = prepare_route(route, policy.into_policy(), &registry)?;
    options.send = packetcraftr::send::Options {
        destination: request.destination,
        plan: request.options,
        build: core::build::Options {
            mode: mode.into(),
            ..core::build::Options::default()
        },
        allow_permissive_live,
    };
    let client = client(Arc::clone(&registry), request.policy);
    let template = core::template::Template::new(request.packet);
    let format = match format {
        ExchangeFormat::Ndjson => {
            let event_stream = stream.clone();
            let summary = client
                .exchange_with_events(&template, options, move |event| {
                    output::exchange::Event::try_from_exchange(event)
                        .map_err(CliError::classified)
                        .and_then(|(event, diagnostics)| {
                            Ok(event_stream.emit_data(event, diagnostics)?)
                        })
                        .map_err(CliError::into_boundary_error)
                })
                .map_err(CliError::classified)?;
            return rendering::render_complete(summary, stream);
        }
        ExchangeFormat::Text => CollectedFormat::Text,
        ExchangeFormat::Json => CollectedFormat::Json,
        ExchangeFormat::Pcap => CollectedFormat::Pcap,
        ExchangeFormat::PcapNg => CollectedFormat::PcapNg,
    };
    let result = client
        .exchange(&template, options)
        .map_err(CliError::classified)?;
    match format {
        CollectedFormat::Text => rendering::render_text(&result),
        CollectedFormat::Json => rendering::render_aggregate(result),
        CollectedFormat::Pcap | CollectedFormat::PcapNg => {
            rendering::render_capture(&result, format.format())
        }
    }
}
