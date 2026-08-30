// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;

use std::time::Duration;

use packetcraftr::{core, output};

use self::arguments::Args;
use super::execution::Executor;
use super::format::ToolFormat;
use super::target_workflow::{self, Document, TargetWorkflow};
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::StreamEncoder;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    let format = ToolFormat::narrow(output::contract::Command::Scan, format)?;
    let Args {
        target,
        transport,
        family,
        ports,
        attempts,
        timeout_ms,
        rate,
        batch_size,
        max_ports,
        max_probes,
        max_duration_ms,
        max_undecoded,
        route,
        limits,
        policy,
    } = arguments;
    let target = parse_target(target)?;
    let queue_limits = limits.into_limits();
    let scan_limits = packetcraftr::scan::Limits {
        max_ports,
        max_probes,
        batch_size,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(CliError::classified)?;
    let ports = conversion::expand_port_specs(&ports, max_ports).map_err(CliError::classified)?;
    let request = packetcraftr::scan::Request {
        target,
        transport: transport.into(),
        address_family: family.into(),
        ports,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: scan_limits,
    };
    let mut probe =
        target_workflow::prepare(route, policy, request.timeout, batch_size, queue_limits)?;
    target_workflow::run::<Scan>(&request, &mut probe, format, stream)
}

/// The `scan` workflow.
pub(super) struct Scan;

impl TargetWorkflow for Scan {
    const COMMAND: output::contract::Command = output::contract::Command::Scan;

    type Request = packetcraftr::scan::Request;
    type Event = packetcraftr::scan::Event;
    type Summary = packetcraftr::scan::Summary;
    type Document = output::scan::Result;
    type Record = output::scan::Event;

    fn execute(
        request: &Self::Request,
        authorizer: &mut impl packetcraftr::target::Authorizer,
        registry: &core::registry::Registry,
        executor: &mut Executor,
        clock: &mut impl packetcraftr::clock::Clock,
    ) -> Result<Document<Self::Document>, CliError> {
        let result = packetcraftr::scan::run(request, authorizer, registry, executor, clock)
            .map_err(CliError::classified)?;
        let (result, diagnostics, stats) =
            output::scan::Result::try_from_scan(result).map_err(CliError::classified)?;
        Ok(Document::new(result, diagnostics, stats))
    }

    fn stream(
        request: &Self::Request,
        authorizer: &mut impl packetcraftr::target::Authorizer,
        registry: &core::registry::Registry,
        executor: &mut Executor,
        clock: &mut impl packetcraftr::clock::Clock,
        stream: &StreamEncoder,
    ) -> Result<(), CliError> {
        let event_stream = stream.clone();
        let summary = packetcraftr::scan::run_with_events(
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
        output::scan::Event::try_from_scan(event).map_err(CliError::classified)
    }

    fn convert_complete(
        summary: Self::Summary,
    ) -> Result<
        (
            Self::Record,
            Vec<core::diagnostic::Diagnostic>,
            output::envelope::Stats,
        ),
        CliError,
    > {
        Ok(output::scan::Event::complete_from_scan(summary))
    }
}
