// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS CLI command logic.

pub(super) mod arguments;
mod conversion;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::DnsArgs;
use crate::errors::CliError;
use crate::rendering::emit_aggregate_with_stats;
use crate::system::{
    DeferredInterface, default_registry_arc, parse_workflow_target,
    validate_live_interface_selector, workflow_exchange_options,
};

use conversion::{generated_dns_source_port, generated_dns_transaction_id};
use execution::CliDnsExecutor;
use rendering::{render_dns_stream, render_dns_text};

pub(super) fn run(arguments: DnsArgs, output: output::contract::Format) -> Result<(), CliError> {
    let DnsArgs {
        server,
        name,
        query_type,
        family,
        port,
        transaction_id,
        source_port,
        no_recursion,
        attempts,
        timeout_ms,
        rate,
        max_duration_ms,
        max_message_bytes,
        max_records,
        max_name_pointers,
        max_txt_strings,
        max_txt_bytes,
        max_rejected_records,
        max_undecoded,
        route,
        limits,
        policy,
    } = arguments;
    let server = parse_workflow_target(server)?;
    let queue_limits = limits.into_limits();
    let request = packetcraftr::dns::Request {
        server,
        address_family: family.into(),
        server_port: port,
        source_port: source_port.unwrap_or_else(generated_dns_source_port),
        query_name: name,
        query_type: query_type.into(),
        transaction_id: transaction_id.unwrap_or_else(generated_dns_transaction_id),
        recursion_desired: !no_recursion,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        queries_per_second: rate,
        limits: packetcraftr::dns::Limits {
            max_message_bytes,
            max_records,
            max_name_pointers,
            max_txt_strings,
            max_txt_bytes,
            max_rejected_records,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_undecoded,
            max_duration: Duration::from_millis(max_duration_ms),
        },
    };
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("dns", route.interface.as_deref())?;

    let registry = default_registry_arc()?;
    let exchange = workflow_exchange_options(
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
        1,
        queue_limits,
    )?;

    let mut executor = CliDnsExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        interface: DeferredInterface::new(route.interface),
    };
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::dns::PolicyAuthorizer::new(&policy, &resolver);
    let mut clock = packetcraftr::clock::SystemClock;
    let result = packetcraftr::dns::run(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(dns_cli_error)?;
    let (result, diagnostics, stats) =
        output::dns::Result::try_from_dns(result).map_err(CliError::classified)?;
    match output {
        output::contract::Format::Text => render_dns_text(result, diagnostics, stats),
        output::contract::Format::Json => {
            emit_aggregate_with_stats(output::contract::Command::Dns, result, diagnostics, stats)
        }
        output::contract::Format::Ndjson => render_dns_stream(result, diagnostics, stats),
        _ => unreachable!("dns format is checked before command dispatch"),
    }
}

pub(crate) fn dns_cli_error(error: packetcraftr::dns::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
