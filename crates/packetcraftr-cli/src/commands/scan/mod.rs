// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan CLI command logic.

pub(super) mod arguments;
mod connect;
mod payload;
mod profiles;
mod rendering;

use packetcraftr_cli::output::contract::ToolFormat;

use std::time::Duration;

use packetcraftr_cli::output;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::rendering::StreamEncoder;

pub(super) fn run(
    arguments: Args,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if arguments.connect && !matches!(arguments.transport, arguments::Transport::Tcp) {
        return Err(CliError::new(
            packetcraftr_core::error::Kind::Cli,
            "--connect requires TCP transport",
        ));
    }
    if arguments.connect && !arguments.route.supports_kernel_tcp() {
        return Err(CliError::from_classification(
            packetcraftr_core::error::Classification::new(
                "capability.scan_tcp_route",
                packetcraftr_core::error::Kind::Capability,
                Some("omit packet interface/source/link overrides for ordinary TCP"),
            ),
            "TCP connect uses kernel route and source selection",
            Vec::new(),
        ));
    }
    let Args {
        connect,
        max_in_flight,
        max_prepared_bytes,
        targets,
        exclusions,
        max_targets,
        transport,
        udp_payload_hex,
        udp_payload_file,
        udp_profiles,
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
    let udp_profiles = profiles::load(udp_profiles.as_deref(), transport)?;
    let targets = packetcraftr::target::Selection {
        include: targets
            .iter()
            .map(|target| target.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(CliError::classified)?,
        exclude: exclusions,
    };
    targets.validate().map_err(CliError::classified)?;
    let queue_limits = limits.into_limits();
    let scan_limits = packetcraftr::scan::Limits {
        max_prepared_bytes,
        max_targets,
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
        max_in_flight,
        targets,
        transport: transport.into(),
        udp_payload,
        udp_profiles,
        address_family: family.into(),
        ports,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: scan_limits,
    };
    if connect {
        return connect::run(&request, policy, format, stream);
    }
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
    if format == ToolFormat::Ndjson {
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
        .map_err(rendering::scan_error)?;
        rendering::emit_complete(summary, stream)
    } else {
        let report = packetcraftr::scan::run(
            &request,
            &mut authorizer,
            &providers.registry,
            &mut providers.executor,
            &mut clock,
        )
        .map_err(rendering::scan_error)?;
        let (result, diagnostics, stats) =
            output::scan::Report::try_from_scan(report).map_err(CliError::classified)?;
        match format {
            ToolFormat::Text => rendering::render_text(result, diagnostics, stats),
            ToolFormat::Json => crate::rendering::emit_aggregate_with_stats(
                output::contract::Command::Scan,
                result,
                diagnostics,
                stats,
            ),
            ToolFormat::Ndjson => Err(CliError::new(
                packetcraftr_core::error::Kind::Internal,
                "NDJSON scan streaming returned before aggregate rendering",
            )),
        }
    }
}

/// Every scan exchange carries exactly one correlated probe.
const MAX_TEMPLATE_PACKETS: usize = 1;
