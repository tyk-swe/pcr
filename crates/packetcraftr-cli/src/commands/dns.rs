// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS CLI command logic.

pub(super) mod arguments;
mod rendering;

use crate::output::contract::ToolFormat;

use packetcraftr_core as core;
use packetcraftr_netio as net;

use crate::output;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::StreamEncoder;

/// A DNS exchange puts exactly one query on the wire per attempt, so the probe
/// only ever needs room for one packet template.
const MAX_TEMPLATE_PACKETS: usize = 1;

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.duration.max_duration())
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_message_bytes: Bytes @ Operation,
            max_records: Count @ Operation,
            max_name_pointers: Count @ Operation,
            max_txt_strings: Count @ Operation,
            max_txt_bytes: Bytes @ Operation,
            max_rejected_records: Count @ ResultRetention,
            max_undecoded: Count @ ResultRetention,
        ]);
        self.timeout.resources(settings);
        self.duration.resources(settings);
        self.limits.resources(settings);
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
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if !arguments.udp_only && !arguments.route.supports_kernel_tcp() {
        return Err(CliError::new(
            core::error::Kind::Usage,
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
    let mut session = providers.session();
    // A lone question keeps the single-query contract: its failure propagates
    // as the command's error rather than reporting as batch evidence.
    if let [request] = requests.as_slice() {
        return execution::run_workflow(
            &mut session,
            format,
            stream,
            crate::cancellation::signal(),
            execution::Hooks {
                command: output::contract::Command::Dns,
                run: Box::new(|session| {
                    packetcraftr::dns::run(
                        request,
                        &mut session.authorizer,
                        session.registry,
                        session.executor,
                        &mut session.clock,
                    )
                    .map_err(CliError::classified)
                }),
                run_with_events: Box::new(|session, emit| {
                    packetcraftr::dns::run_with_events(
                        request,
                        &mut session.authorizer,
                        session.registry,
                        session.executor,
                        &mut session.clock,
                        session.runtime,
                        emit,
                    )
                    .map_err(CliError::classified)
                }),
                on_event: rendering::emit_event,
                into_result: Box::new(|report| {
                    output::envelope::Published::<output::dns::Report>::try_from(report)
                        .map_err(CliError::classified)
                }),
                render_text: Box::new(|report, _| {
                    rendering::render_text(
                        output::envelope::Published::try_from(report)
                            .map_err(CliError::classified)?,
                    )
                }),
                complete: rendering::emit_complete,
            },
        );
    }
    execution::run_workflow(
        &mut session,
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Dns,
            run: Box::new(|session| {
                packetcraftr::dns::run_batch(
                    &requests,
                    &mut session.authorizer,
                    session.registry,
                    session.executor,
                    &mut session.clock,
                )
                .map_err(CliError::classified)
            }),
            run_with_events: Box::new(|session, emit| {
                packetcraftr::dns::run_batch_with_events(
                    &requests,
                    &mut session.authorizer,
                    session.registry,
                    session.executor,
                    &mut session.clock,
                    session.runtime,
                    emit,
                )
                .map_err(CliError::classified)
            }),
            on_event: rendering::emit_event,
            into_result: Box::new(|batch| {
                output::envelope::Published::<output::dns::BatchResult>::try_from(batch)
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|batch, _| {
                rendering::render_batch_text(
                    output::envelope::Published::try_from(batch).map_err(CliError::classified)?,
                )
            }),
            complete: rendering::emit_batch_complete,
        },
    )
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
            core::error::Kind::Usage,
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
    // Use independent random ports per question to retain anti-spoofing
    // entropy, unless `--source-port` pins them or TCP delegates selection to
    // the stack.
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
        max_duration: arguments.duration.max_duration(),
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
                timeout: arguments.timeout.timeout(),
                queries_per_second: arguments.rate,
                limits,
            })
        })
        .collect()
}
