// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Raw scan execution: final workflow setup, follow-up composition, and
//! streaming or collected publication.

use packetcraftr::scan::followup;

use super::traceroute;
use crate::errors::CliError;
use crate::invocation::StreamEncoder;
use crate::output::{self, contract::Format};
use crate::system::{Runtime, prepare_workflow};

/// The fully validated raw scan boundary. Preparation has already selected
/// endpoints, method, publication plan, and optional follow-up stages.
pub(super) struct Request {
    pub(super) request: packetcraftr::scan::Request,
    pub(super) plan: output::scan::plan::Plan,
    pub(super) policy: crate::command_options::HostnamePolicyArgs,
    pub(super) route: crate::command_options::RouteSelectionArgs,
    pub(super) queue_limits: packetcraftr_netio::capture::Limits,
    pub(super) trace_stage: Option<traceroute::Stage>,
    pub(super) reverse_dns: Option<packetcraftr::target::Target>,
    pub(super) reverse_dns_port: u16,
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    run: Request,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let Request {
        request,
        plan,
        policy,
        route,
        queue_limits,
        trace_stage,
        reverse_dns,
        reverse_dns_port,
    } = run;
    let workflow = prepare_workflow(&route, policy.into_policy(), request.timeout, queue_limits)?;
    let client = workflow.client(invocation, Runtime::Workflow);
    let request = packetcraftr::scan::Request {
        route: workflow.route,
        collection: workflow.collection,
        ..request
    };
    // The finalized template is validated again before the scan runs, so a
    // queue configuration the trace stage cannot use fails before any probe.
    if let Some(stage) = &trace_stage {
        stage.revalidate(&request)?;
    }
    // DNS over TCP cannot follow a packet route override.
    let reverse = reverse_dns
        .map(|server| {
            let transport = if route.supports_kernel_tcp() {
                packetcraftr::dns::TransportMode::UdpThenTcp
            } else {
                packetcraftr::dns::TransportMode::Udp
            };
            super::validated_reverse_dns(
                followup::ReverseDns {
                    server,
                    server_port: reverse_dns_port,
                    transport,
                },
                &request,
            )
        })
        .transpose()?;
    let trace_plan = trace_stage.as_ref().map(traceroute::Stage::plan);
    let request = followup::Request {
        trace: trace_stage.as_ref().map(|stage| stage.trace(invocation)),
        reverse_dns: reverse,
        scan: request,
    };
    match format {
        Format::Ndjson => {
            let emit =
                crate::commands::execution::emitter(invocation, super::streaming::emit_event);
            let mut report = client
                .scan_with_followups(request, emit)
                .map_err(super::followup_error)?;
            report.scan.stats = report.stats;
            let traceroute = trace_plan.zip(report.trace).map(|(plan, traced)| {
                output::traceroute::hosts::Complete {
                    plan,
                    retained_evidence_bytes: traced.retained_evidence_bytes,
                }
            });
            let summary = Streamed {
                report: report.scan,
                endpoints: report.endpoints,
                plan,
                reverse_dns: super::reverse_dns_hosts(report.reverse_dns),
                traceroute,
            };
            invocation.check()?;
            super::streaming::emit_complete(summary, stream)
        }
        format => {
            let collector = followup::Collector::default();
            let report = client
                .scan_with_followups(request, collector.clone())
                .map_err(super::followup_error)?;
            let aggregate = collector.finish(report).map_err(super::followup_error)?;
            let followup::Aggregate {
                mut scan,
                trace,
                reverse_dns,
                stats,
            } = aggregate;
            scan.stats = stats;
            if let Some(trace) = &trace {
                scan.diagnostics.extend(trace.diagnostics.iter().cloned());
            }
            let traced = trace_plan.zip(trace);
            invocation.check()?;
            let published = output::scan::Report::publish(
                scan,
                plan,
                super::reverse_dns_hosts(reverse_dns),
                traced
                    .map(|(plan, aggregate)| {
                        output::traceroute::hosts::Report::new(plan, aggregate)
                    })
                    .transpose()
                    .map_err(CliError::classified)?,
            )
            .map_err(CliError::classified)?;
            if format == Format::Json {
                crate::rendering::emit_published(
                    invocation,
                    output::contract::Command::Scan,
                    published,
                )
            } else {
                super::rendering::render_text(invocation, published, stream.presentation())
            }
        }
    }
}

pub(super) struct Streamed {
    pub(super) report: packetcraftr::scan::Report,
    pub(super) endpoints: Vec<packetcraftr::scan::Endpoint>,
    pub(super) plan: output::scan::plan::Plan,
    /// Each host's PTR lookup, by position; empty when none ran.
    pub(super) reverse_dns: Vec<Option<output::scan::host::ReverseDns>>,
    pub(super) traceroute: Option<output::traceroute::hosts::Complete>,
}
