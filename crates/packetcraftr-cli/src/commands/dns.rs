// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use crate::output::contract::Format;

use packetcraftr_core as core;
use packetcraftr_netio as net;

use crate::output;

use self::arguments::Args;
use super::execution;
use crate::command_options::parse_target;
use crate::errors::CliError;
use crate::rendering::StreamEncoder;
use crate::system::{Runtime, prepare_workflow};

impl super::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
    ];
    const CANCELLATION: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
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
        format: Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    if !arguments.udp_only && !arguments.route.supports_kernel_tcp() {
        return Err(CliError::new(
            core::error::Kind::Usage,
            "DNS TCP cannot preserve --interface, --source, or --link-mode; remove the route override or select --udp-only",
        ));
    }
    let queue_limits = arguments.limits.clone().into_limits();
    let mut requests = prepare_requests(&arguments, queue_limits)?;
    let workflow = prepare_workflow(
        &arguments.route,
        arguments.policy.into_policy(),
        requests[0].timeout,
        queue_limits,
    )?;
    for request in &mut requests {
        request.route = workflow.route.clone();
        request.collection = workflow.collection.clone();
    }
    let client = &workflow.client(Runtime::Workflow);
    // A lone question keeps the single-query contract.
    if let [request] = requests.as_slice() {
        return execution::run_workflow(
            format,
            stream,
            crate::cancellation::signal(),
            execution::Hooks {
                command: output::contract::Command::Dns,
                run: Box::new(|| {
                    let collector = packetcraftr::dns::Collector::default();
                    let report = client
                        .dns(request.clone(), collector.clone())
                        .map_err(CliError::classified)?;
                    collector.finish(report).map_err(CliError::classified)
                }),
                run_with_events: Box::new(|emit| {
                    client
                        .dns(request.clone(), emit)
                        .map_err(CliError::classified)
                }),
                on_event: rendering::emit_event,
                into_result: Box::new(|aggregate| {
                    output::envelope::Published::<output::dns::Report>::try_from(aggregate)
                        .map_err(CliError::classified)
                }),
                render: Box::new(|aggregate, _| {
                    rendering::render_text(
                        output::envelope::Published::try_from(aggregate)
                            .map_err(CliError::classified)?,
                    )
                }),
                complete: rendering::emit_complete,
            },
        );
    }
    let request = packetcraftr::dns::batch::Request {
        questions: requests,
    };
    execution::run_workflow(
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Dns,
            run: Box::new(|| {
                let collector = packetcraftr::dns::batch::Collector::default();
                let report = client
                    .dns_batch(request.clone(), collector.clone())
                    .map_err(CliError::classified)?;
                collector.finish(report).map_err(CliError::classified)
            }),
            run_with_events: Box::new(|emit| {
                client
                    .dns_batch(request.clone(), emit)
                    .map_err(CliError::classified)
            }),
            on_event: rendering::emit_batch_event,
            into_result: Box::new(|aggregate| {
                output::envelope::Published::<output::dns::BatchResult>::try_from(aggregate)
                    .map_err(CliError::classified)
            }),
            render: Box::new(|aggregate, _| {
                rendering::render_batch_text(
                    output::envelope::Published::try_from(aggregate)
                        .map_err(CliError::classified)?,
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
    if questions.len() > packetcraftr::dns::batch::MAX_QUESTIONS {
        return Err(CliError::classified(
            packetcraftr::dns::Error::InvalidLimit {
                field: "questions",
                value: questions.len() as u64,
                reason: format!(
                    "must be within 1..={}",
                    packetcraftr::dns::batch::MAX_QUESTIONS
                ),
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
    // Independent random ports per question retain anti-spoofing entropy.
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
                route: packetcraftr::route::Options::default(),
                collection: packetcraftr::exchange::Collection::default(),
            })
        })
        .collect()
}
