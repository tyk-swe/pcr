// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use packetcraftr_cli::output::contract::ExchangeFormat;

use std::time::Duration;

use packetcraftr_core::analysis::pcap as capture;
use packetcraftr_core::error::Kind;

use packetcraftr_cli::output;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::StreamEncoder;

pub(super) fn run(
    arguments: Args,
    format: ExchangeFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let compression = arguments.send.compression;
    compression.validate(format.as_format())?;
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
    let first =
        crate::system::authorize_expanded_destinations(&template, max_template_packets, &policy)?;
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
    // Exchange drives the composed client itself — authorization,
    // cancellation, and the callback runtime live inside it — so the driver
    // vends no session state.
    execution::run_workflow(
        &mut (),
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Exchange,
            conversion: output::exchange::Conversion,
            run: Box::new(|_| {
                client
                    .exchange(&template, options.clone())
                    .map_err(CliError::classified)
            }),
            run_with_events: Box::new(|_, emit| {
                client
                    .exchange_with_events(&template, options.clone(), emit)
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(move |converted, format| match format {
                ExchangeFormat::Text => rendering::render_text(&converted),
                ExchangeFormat::Pcap => {
                    rendering::render_capture(&converted, capture::Format::Pcap, compression)
                }
                ExchangeFormat::PcapNg => {
                    rendering::render_capture(&converted, capture::Format::PcapNg, compression)
                }
                ExchangeFormat::Json | ExchangeFormat::Ndjson => Err(CliError::new(
                    Kind::Internal,
                    "exchange machine formats dispatch before text rendering",
                )),
            }),
        },
    )
}
