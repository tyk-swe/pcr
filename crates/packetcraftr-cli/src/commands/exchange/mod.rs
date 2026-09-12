// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use packetcraftr_cli::output::contract::Format;

use std::time::Duration;

use packetcraftr_core::analysis::pcap as capture;
use packetcraftr_core::error::Kind;

use packetcraftr_cli::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::StreamEncoder;

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let Args {
        send,
        template,
        timeout_ms,
        max_responses,
        max_unmatched_frames,
        limits,
    } = arguments;
    let max_template_packets = template.max_template_packets;
    let axes = template.parse()?;
    let limits = limits.into_limits();
    let mut options = packetcraftr::exchange::Options {
        timeout: Duration::from_millis(timeout_ms),
        max_template_packets,
        max_responses,
        max_unmatched_frames,
        capture: limits,
        ..packetcraftr::exchange::Options::default()
    };
    options.decode.max_packet_size = limits.snap_length;
    // Validate before packet parsing can trigger hostname/interface work.
    options.validate().map_err(CliError::classified)?;

    let registry = packetcraftr_core::protocol::builtin::registry();
    let packet = read_recipe(
        send.route.recipe,
        &registry,
        packetcraftr_core::layout::DEFAULT_MAX_LAYERS,
    )?;
    let template = axes.into_template(packet);
    let policy = send.policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let count = template.expansion_len().map_err(CliError::classified)?;
    policy
        .authorize(packetcraftr::policy::Operation::Budgeted(
            packetcraftr::policy::WireBudget::new(u64::try_from(count).unwrap_or(u64::MAX), 0),
        ))
        .map_err(CliError::classified)?;
    let mut packets = template
        .expand(max_template_packets)
        .map_err(CliError::classified)?;
    let first = packets
        .next()
        .transpose()
        .map_err(CliError::classified)?
        .ok_or_else(|| CliError::new(Kind::Cli, "packet set must contain at least one packet"))?;
    // Authorize actual expanded destinations before hostname or interface work.
    // The library repeats these checks against every final packet before sending.
    policy
        .authorize_packet_destinations(&first)
        .map_err(CliError::classified)?;
    for packet in packets {
        crate::cancellation::check()?;
        policy
            .authorize_packet_destinations(&packet.map_err(CliError::classified)?)
            .map_err(CliError::classified)?;
    }
    let prepared = crate::system::prepare_packet_route(
        first,
        send.route.destination,
        send.route.route,
        policy,
    )?;
    options.send = packetcraftr::send::Options {
        destination: prepared.destination,
        plan: prepared.options,
        build: packetcraftr_core::build::Options {
            mode: send.mode.into(),
            ..packetcraftr_core::build::Options::default()
        },
        allow_permissive_live: send.allow_permissive_live,
    };
    let client = crate::system::client(registry, prepared.policy);
    if format == Format::Ndjson {
        let event_stream = stream.clone();
        let summary = client
            .exchange_with_events(&template, options, move |event| {
                output::exchange::Event::try_from_exchange(event)
                    .map_err(CliError::classified)
                    .and_then(
                        |(event, diagnostics)| Ok(event_stream.emit_data(event, diagnostics)?),
                    )
                    .map_err(CliError::into_boundary_error)
            })
            .map_err(CliError::classified)?;
        return rendering::render_complete(summary, stream);
    }
    let result = client
        .exchange(&template, options)
        .map_err(CliError::classified)?;
    match format {
        Format::Text => rendering::render_text(&result),
        Format::Json => rendering::render_aggregate(result),
        Format::Pcap => rendering::render_capture(&result, capture::Format::Pcap),
        Format::PcapNg => rendering::render_capture(&result, capture::Format::PcapNg),
        _ => unreachable!("streaming returned before aggregate rendering"),
    }
}
