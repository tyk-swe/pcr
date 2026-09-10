// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS CLI command logic.

pub(super) mod arguments;
mod rendering;

use packetcraftr_cli::output::contract::Format;

use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_netio as net;

use packetcraftr_cli::output;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::StreamEncoder;

/// A DNS exchange puts exactly one query on the wire per attempt, so the probe
/// only ever needs room for one packet template.
const MAX_TEMPLATE_PACKETS: usize = 1;

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    if !arguments.udp_only && !arguments.route.supports_kernel_tcp() {
        return Err(CliError::new(
            core::error::Kind::Cli,
            "DNS TCP cannot preserve --interface, --source, or --link-mode; remove the route override or select --udp-only",
        ));
    }
    let queue_limits = arguments.limits.clone().into_limits();
    let request = prepare_request(&arguments, queue_limits)?;
    let mut providers = execution::prepare(
        arguments.route,
        arguments.policy,
        request.timeout,
        MAX_TEMPLATE_PACKETS,
        queue_limits,
    )?;
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::policy::PolicyAuthorizer::new(&providers.policy, &resolver);
    let mut clock = packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone());
    if format == Format::Ndjson {
        let events = stream.clone();
        let summary = packetcraftr::dns::run_with_events(
            &request,
            &mut authorizer,
            &providers.registry,
            &mut providers.executor,
            &mut clock,
            &providers.runtime,
            move |event| {
                rendering::emit_event(event, &events).map_err(CliError::into_boundary_error)
            },
        )
        .map_err(CliError::classified)?;
        rendering::emit_complete(summary, stream)
    } else {
        let report = packetcraftr::dns::run(
            &request,
            &mut authorizer,
            &providers.registry,
            &mut providers.executor,
            &mut clock,
        )
        .map_err(CliError::classified)?;
        let (result, diagnostics, stats) =
            output::dns::Report::try_from_dns(report).map_err(CliError::classified)?;
        if format == Format::Text {
            rendering::render_text(result, diagnostics, stats)
        } else {
            crate::rendering::emit_aggregate_with_stats(
                output::contract::Command::Dns,
                result,
                diagnostics,
                stats,
            )
        }
    }
}

fn prepare_request(
    arguments: &Args,
    queue_limits: net::capture::Limits,
) -> Result<packetcraftr::dns::Request, CliError> {
    let request = packetcraftr::dns::Request {
        server: parse_target(arguments.server.clone())?,
        address_family: arguments.family.into(),
        server_port: arguments.port,
        source_port: match arguments.source_port {
            None if arguments.tcp => 0,
            Some(port) => port,
            None => packetcraftr::dns::unpredictable_source_port().map_err(CliError::classified)?,
        },
        query_name: arguments.name.clone(),
        query_type: arguments.query_type,
        transaction_id: match arguments.transaction_id {
            Some(id) => id,
            None => {
                packetcraftr::dns::unpredictable_transaction_id().map_err(CliError::classified)?
            }
        },
        recursion_desired: !arguments.no_recursion,
        edns: arguments.edns_udp_payload_size.map(|udp_payload_size| {
            packetcraftr::dns::EdnsRequest {
                udp_payload_size,
                dnssec_ok: arguments.dnssec_ok,
            }
        }),
        transport: if arguments.tcp {
            packetcraftr::dns::TransportMode::Tcp
        } else if arguments.udp_only {
            packetcraftr::dns::TransportMode::Udp
        } else {
            packetcraftr::dns::TransportMode::UdpThenTcp
        },
        attempts: arguments.attempts,
        timeout: Duration::from_millis(arguments.timeout_ms),
        queries_per_second: arguments.rate,
        limits: packetcraftr::dns::Limits {
            message: packetcraftr::dns::MessageLimits {
                max_message_bytes: arguments.max_message_bytes,
                max_records: arguments.max_records,
                max_name_pointers: arguments.max_name_pointers,
                max_txt_strings: arguments.max_txt_strings,
                max_txt_bytes: arguments.max_txt_bytes,
                max_rejected_records: arguments.max_rejected_records,
            },
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_undecoded: arguments.max_undecoded,
            max_duration: Duration::from_millis(arguments.max_duration_ms),
        },
    };
    Ok(request)
}
