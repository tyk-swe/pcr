// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;

use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::Args;
use super::execution::Executor;
use super::format::ToolFormat;
use super::target_workflow::{self, Document, TargetWorkflow};
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::NdjsonStream;

/// A DNS exchange puts exactly one query on the wire per attempt, so the probe
/// only ever needs room for one packet template.
const MAX_TEMPLATE_PACKETS: usize = 1;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let format = ToolFormat::narrow(output::contract::Command::Dns, format)?;
    let queue_limits = arguments.limits.clone().into_limits();
    let request = prepare_request(&arguments, queue_limits)?;
    let mut probe = target_workflow::prepare(
        arguments.route,
        arguments.policy,
        request.timeout,
        MAX_TEMPLATE_PACKETS,
        queue_limits,
    )?;
    target_workflow::run::<Dns>(&request, &mut probe, format, stream)
}

fn prepare_request(
    arguments: &Args,
    queue_limits: net::capture::Limits,
) -> Result<packetcraftr::dns::Request, CliError> {
    let request = packetcraftr::dns::Request {
        server: parse_target(arguments.server.clone())?,
        address_family: arguments.family.into(),
        server_port: arguments.port,
        source_port: arguments
            .source_port
            .unwrap_or_else(conversion::source_port),
        query_name: arguments.name.clone(),
        query_type: arguments.query_type.into(),
        transaction_id: arguments
            .transaction_id
            .unwrap_or_else(conversion::transaction_id),
        recursion_desired: !arguments.no_recursion,
        attempts: arguments.attempts,
        timeout: Duration::from_millis(arguments.timeout_ms),
        queries_per_second: arguments.rate,
        limits: packetcraftr::dns::Limits {
            max_message_bytes: arguments.max_message_bytes,
            max_records: arguments.max_records,
            max_name_pointers: arguments.max_name_pointers,
            max_txt_strings: arguments.max_txt_strings,
            max_txt_bytes: arguments.max_txt_bytes,
            max_rejected_records: arguments.max_rejected_records,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_undecoded: arguments.max_undecoded,
            max_duration: Duration::from_millis(arguments.max_duration_ms),
        },
    };
    Ok(request)
}

/// The `dns` workflow.
pub(super) struct Dns;

impl TargetWorkflow for Dns {
    const COMMAND: output::contract::Command = output::contract::Command::Dns;

    type Request = packetcraftr::dns::Request;
    type Event = packetcraftr::dns::Event;
    type Summary = packetcraftr::dns::Summary;
    type Document = output::dns::Result;
    type Record = output::dns::Event;

    fn execute(
        request: &Self::Request,
        authorizer: &mut impl packetcraftr::target::Authorizer,
        registry: &core::registry::Registry,
        executor: &mut Executor,
        clock: &mut impl packetcraftr::clock::Clock,
    ) -> Result<Document<Self::Document>, CliError> {
        let result = packetcraftr::dns::run(request, authorizer, registry, executor, clock)
            .map_err(CliError::classified)?;
        let (result, diagnostics, stats) =
            output::dns::Result::try_from_dns(result).map_err(CliError::classified)?;
        Ok(Document::new(result, diagnostics, stats))
    }

    fn stream(
        request: &Self::Request,
        authorizer: &mut impl packetcraftr::target::Authorizer,
        registry: &core::registry::Registry,
        executor: &mut Executor,
        clock: &mut impl packetcraftr::clock::Clock,
        stream: &NdjsonStream,
    ) -> Result<(), CliError> {
        let event_stream = stream.clone();
        let summary = packetcraftr::dns::run_with_events(
            request,
            authorizer,
            registry,
            executor,
            clock,
            move |event| {
                Self::emit_event(event, &event_stream).map_err(CliError::into_boundary_error)
            },
        )
        .map_err(CliError::classified)?;
        Self::emit_complete(summary, stream)
    }

    fn render_text(document: Document<Self::Document>) -> Result<(), CliError> {
        rendering::render_text(document.result, document.diagnostics, document.stats)
    }

    fn convert_event(
        event: Self::Event,
    ) -> Result<(Self::Record, Vec<core::diagnostic::Diagnostic>), CliError> {
        output::dns::Event::try_from_dns(event).map_err(CliError::classified)
    }

    fn convert_complete(
        summary: Self::Summary,
    ) -> (
        Self::Record,
        Vec<core::diagnostic::Diagnostic>,
        output::envelope::Stats,
    ) {
        output::dns::Event::complete_from_dns(summary)
    }
}
