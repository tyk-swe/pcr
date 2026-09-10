// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan CLI command logic.

pub(super) mod arguments;
mod payload;
mod rendering;

use packetcraftr_cli::output::contract::Format;

use std::time::Duration;

use packetcraftr_cli::output;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::StreamEncoder;

pub(super) fn run(arguments: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    let Args {
        target,
        transport,
        udp_payload_hex,
        udp_payload_file,
        family,
        ports,
        attempts,
        timeout_ms,
        rate,
        max_ports,
        max_probes,
        max_duration_ms,
        max_undecoded,
        route,
        limits,
        policy,
    } = arguments;
    let udp_payload = payload::read(
        transport,
        udp_payload_hex.as_deref(),
        udp_payload_file.as_deref(),
    )?;
    let target = parse_target(target)?;
    let queue_limits = limits.into_limits();
    let scan_limits = packetcraftr::scan::Limits {
        max_ports,
        max_probes,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(CliError::classified)?;
    let ports = packetcraftr::scan::select_ports(ports.into_iter().map(|spec| spec.0), max_ports)
        .map_err(CliError::classified)?;
    let request = packetcraftr::scan::Request {
        target,
        transport: transport.into(),
        udp_payload,
        address_family: family.into(),
        ports,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: scan_limits,
    };
    let mut providers = execution::prepare(
        route,
        policy,
        request.timeout,
        MAX_TEMPLATE_PACKETS,
        queue_limits,
    )?;
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::policy::PolicyAuthorizer::new(&providers.policy, &resolver);
    let mut clock = packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone());
    if format == Format::Ndjson {
        let events = stream.clone();
        let summary = packetcraftr::scan::run_with_events(
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
        let report = packetcraftr::scan::run(
            &request,
            &mut authorizer,
            &providers.registry,
            &mut providers.executor,
            &mut clock,
        )
        .map_err(CliError::classified)?;
        let (result, diagnostics, stats) =
            output::scan::Report::try_from_scan(report).map_err(CliError::classified)?;
        if format == Format::Text {
            rendering::render_text(result, diagnostics, stats)
        } else {
            crate::rendering::emit_aggregate_with_stats(
                output::contract::Command::Scan,
                result,
                diagnostics,
                stats,
            )
        }
    }
}

/// Every scan exchange carries exactly one correlated probe.
const MAX_TEMPLATE_PACKETS: usize = 1;
