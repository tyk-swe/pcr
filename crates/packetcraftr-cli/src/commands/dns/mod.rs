// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS CLI command logic.

pub(super) mod arguments;
mod rendering;

use packetcraftr_cli::output::contract::ToolFormat;

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

pub(super) fn run(
    arguments: Args,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if !arguments.udp_only && !arguments.route.supports_kernel_tcp() {
        return Err(CliError::new(
            core::error::Kind::Cli,
            "DNS TCP cannot preserve --interface, --source, or --link-mode; remove the route override or select --udp-only",
        ));
    }
    let queue_limits = arguments.limits.clone().into_limits();
    let requests = prepare_requests(&arguments, queue_limits)?;
    let mut providers = execution::prepare(
        arguments.route,
        arguments.policy,
        requests[0].timeout,
        MAX_TEMPLATE_PACKETS,
        queue_limits,
    )?;
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::policy::PolicyAuthorizer::new(&providers.policy, &resolver);
    let mut clock = packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone());
    // A lone question keeps the single-query contract: its failure propagates
    // as the command's error rather than reporting as batch evidence.
    if let [request] = requests.as_slice() {
        return run_single(
            request,
            format,
            stream,
            Channels {
                registry: &providers.registry,
                executor: &mut providers.executor,
                runtime: &providers.runtime,
            },
            &mut authorizer,
            &mut clock,
        );
    }
    if format == ToolFormat::Ndjson {
        let events = stream.clone();
        let batch = packetcraftr::dns::run_batch_with_events(
            &requests,
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
        rendering::emit_batch_complete(batch, stream)
    } else {
        let batch = packetcraftr::dns::run_batch(
            &requests,
            &mut authorizer,
            &providers.registry,
            &mut providers.executor,
            &mut clock,
        )
        .map_err(CliError::classified)?;
        let (result, diagnostics, stats) =
            output::dns::BatchResult::try_from_batch(batch).map_err(CliError::classified)?;
        match format {
            ToolFormat::Text => rendering::render_batch_text(result, diagnostics, stats),
            ToolFormat::Json => crate::rendering::emit_aggregate_with_stats(
                output::contract::Command::Dns,
                result,
                diagnostics,
                stats,
            ),
            ToolFormat::Ndjson => Err(CliError::new(
                core::error::Kind::Internal,
                "NDJSON DNS batch streaming returned before aggregate rendering",
            )),
        }
    }
}

/// The prepared provider channels a query executes through.
struct Channels<'a> {
    registry: &'a core::registry::Registry,
    executor: &'a mut execution::Executor,
    runtime: &'a packetcraftr::progress::Runtime,
}

fn run_single(
    request: &packetcraftr::dns::Request,
    format: ToolFormat,
    stream: &StreamEncoder,
    channels: Channels<'_>,
    authorizer: &mut packetcraftr::policy::PolicyAuthorizer<'_>,
    clock: &mut packetcraftr::clock::CancellableClock,
) -> Result<(), CliError> {
    let Channels {
        registry,
        executor,
        runtime,
    } = channels;
    if format == ToolFormat::Ndjson {
        let events = stream.clone();
        let summary = packetcraftr::dns::run_with_events(
            request,
            authorizer,
            registry,
            executor,
            clock,
            runtime,
            move |event| {
                rendering::emit_event(event, &events).map_err(CliError::into_boundary_error)
            },
        )
        .map_err(CliError::classified)?;
        rendering::emit_complete(summary, stream)
    } else {
        let report = packetcraftr::dns::run(request, authorizer, registry, executor, clock)
            .map_err(CliError::classified)?;
        let (result, diagnostics, stats) =
            output::dns::Report::try_from_dns(report).map_err(CliError::classified)?;
        match format {
            ToolFormat::Text => rendering::render_text(result, diagnostics, stats),
            ToolFormat::Json => crate::rendering::emit_aggregate_with_stats(
                output::contract::Command::Dns,
                result,
                diagnostics,
                stats,
            ),
            ToolFormat::Ndjson => Err(CliError::new(
                core::error::Kind::Internal,
                "NDJSON DNS streaming returned before aggregate rendering",
            )),
        }
    }
}

fn prepare_requests(
    arguments: &Args,
    queue_limits: net::capture::Limits,
) -> Result<Vec<packetcraftr::dns::Request>, CliError> {
    // NAME questions use --type; --reverse questions are always PTR.
    let mut questions: Vec<(String, packetcraftr::dns::QueryType)> = arguments
        .names
        .iter()
        .map(|name| (name.clone(), arguments.query_type))
        .collect();
    questions.extend(arguments.reverse.iter().map(|address| {
        (
            packetcraftr::dns::reverse_name(*address),
            packetcraftr::dns::QueryType::PTR,
        )
    }));
    if questions.len() > packetcraftr::dns::MAX_QUESTIONS {
        return Err(CliError::classified(
            packetcraftr::dns::Error::InvalidLimit {
                field: "questions",
                value: questions.len() as u64,
                reason: format!("must be within 1..={}", packetcraftr::dns::MAX_QUESTIONS),
            },
        ));
    }
    if questions.len() > 1 && arguments.transaction_id.is_some() {
        return Err(CliError::new(
            core::error::Kind::Cli,
            "--transaction-id is only valid for a single-question batch",
        ));
    }
    let server = parse_target(arguments.server.clone())?;
    let transport = if arguments.tcp {
        packetcraftr::dns::TransportMode::Tcp
    } else if arguments.udp_only {
        packetcraftr::dns::TransportMode::Udp
    } else {
        packetcraftr::dns::TransportMode::UdpThenTcp
    };
    // An explicit --source-port pins every question, and the TCP path lets the
    // stack choose. Otherwise each question draws its own port below, so one
    // observed query does not narrow the anti-spoofing entropy of the rest —
    // the same reason a shared --transaction-id is rejected for a batch.
    let pinned_source_port = arguments.source_port.or(arguments.tcp.then_some(0));
    let limits = packetcraftr::dns::Limits {
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
    };
    questions
        .into_iter()
        .map(|(query_name, query_type)| {
            let transaction_id = match arguments.transaction_id {
                Some(id) => id,
                None => packetcraftr::dns::unpredictable_transaction_id()
                    .map_err(CliError::classified)?,
            };
            let source_port = match pinned_source_port {
                Some(port) => port,
                None => {
                    packetcraftr::dns::unpredictable_source_port().map_err(CliError::classified)?
                }
            };
            Ok(packetcraftr::dns::Request {
                server: server.clone(),
                address_family: arguments.family.into(),
                server_port: arguments.port,
                source_port,
                query_name,
                query_type,
                transaction_id,
                recursion_desired: !arguments.no_recursion,
                edns: arguments.edns_udp_payload_size.map(|udp_payload_size| {
                    packetcraftr::dns::EdnsRequest {
                        udp_payload_size,
                        dnssec_ok: arguments.dnssec_ok,
                    }
                }),
                transport,
                attempts: arguments.attempts,
                timeout: Duration::from_millis(arguments.timeout_ms),
                queries_per_second: arguments.rate,
                limits,
            })
        })
        .collect()
}
