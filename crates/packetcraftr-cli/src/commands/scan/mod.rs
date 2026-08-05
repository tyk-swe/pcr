// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan CLI command logic.

mod conversion;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{client, net, output, packet, workflow};

use crate::arguments::ScanArgs;
use crate::errors::CliError;
use crate::rendering::emit_json;
use crate::runtime::{
    DeferredInterface, default_registry_arc, parse_workflow_target, workflow_exchange_options,
};

pub(crate) use conversion::validate_live_interface_selector;

use execution::CliScanExecutor;
use rendering::{render_scan_stream, render_scan_text};

pub(crate) fn run_scan(
    arguments: ScanArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let ScanArgs {
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
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let target = parse_workflow_target(target)?;
    let queue_limits = limits.into_limits();
    let scan_limits = workflow::scan::Limits {
        max_ports,
        max_probes,
        batch_size,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(scan_cli_error)?;
    let ports = conversion::expand_port_specs(&ports, max_ports).map_err(scan_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("scan", interface.as_deref())?;
    let request = workflow::scan::Request {
        target,
        transport: transport.into(),
        address_family: family.into(),
        ports,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: scan_limits,
    };
    let registry = default_registry_arc()?;
    let exchange = workflow_exchange_options(
        client::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: link_mode.into(),
                interface: None,
                preferred_source: source,
            },
            build: packet::build::Options::default(),
            allow_permissive_live: false,
        },
        request.timeout,
        batch_size,
        queue_limits,
    )?;

    let mut executor = CliScanExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        interface: DeferredInterface::new(interface),
    };
    let resolver = client::target::SystemResolver;
    let mut authorizer = workflow::scan::PolicyAuthorizer::new(&policy, &resolver);
    let mut clock = workflow::clock::SystemClock;
    let result = workflow::scan::run(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(scan_cli_error)?;
    let (result, diagnostics, stats) =
        output::scan::Result::try_from_scan(result).map_err(CliError::classified)?;

    match output {
        output::contract::Format::Text => render_scan_text(result, diagnostics, stats),
        output::contract::Format::Json => emit_json(
            &output::envelope::Aggregate::success(
                output::contract::Command::Scan,
                result,
                diagnostics,
            )
            .with_stats(stats),
        ),
        output::contract::Format::Ndjson => render_scan_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Scan,
                format: output,
            },
        )),
    }
}

pub(crate) fn scan_cli_error(error: workflow::scan::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
