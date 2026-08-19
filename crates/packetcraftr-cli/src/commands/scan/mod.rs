// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan CLI command logic.

pub(super) mod arguments;
mod conversion;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::Args;
use super::registry;
use crate::errors::CliError;
use crate::input::parse_target;
use crate::rendering::NdjsonStream;
use crate::system::{DeferredInterface, client, exchange, validate_selector};

use execution::Executor;

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
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
    scan_limits.validate().map_err(classified_error)?;
    let ports = conversion::expand_port_specs(&ports, max_ports).map_err(classified_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_selector(route.interface.as_deref()).map(|_| ())?;
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
    let registry = registry()?;
    let exchange = exchange::options(
        packetcraftr::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: route.link_mode.into(),
                interface: None,
                preferred_source: route.source,
            },
            build: core::build::Options::default(),
            allow_permissive_live: false,
        },
        request.timeout,
        batch_size,
        queue_limits,
    )?;

    let mut executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface: DeferredInterface::new(route.interface),
    };
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::target::PolicyAuthorizer::new(&policy, &resolver);
    let mut clock = packetcraftr::clock::SystemClock;
    let result = packetcraftr::scan::run(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(classified_error)?;
    let (result, diagnostics, stats) =
        output::scan::Result::try_from_scan(result).map_err(CliError::classified)?;

    match format {
        output::contract::Format::Text => rendering::render_text(result, diagnostics, stats),
        output::contract::Format::Json => rendering::render_aggregate(result, diagnostics, stats),
        output::contract::Format::Ndjson => {
            rendering::render_stream(result, diagnostics, stats, stream)
        }
        _ => unreachable!("scan format is checked before command dispatch"),
    }
}

pub(crate) fn classified_error(error: packetcraftr::scan::Error) -> CliError {
    CliError::classified(error)
}
