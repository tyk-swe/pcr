// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Fuzz CLI command logic.

pub(super) mod arguments;
mod execution;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};

use self::arguments::FuzzArgs;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::emit_aggregate_with_stats;
use crate::system::{
    DeferredInterface, default_registry_arc, system_client, validate_live_interface_selector,
    workflow_exchange_options,
};

use execution::CliFuzzExecutor;
use rendering::{render_fuzz_stream, render_fuzz_text};

pub(super) fn run(arguments: FuzzArgs, output: output::contract::Format) -> Result<(), CliError> {
    let FuzzArgs {
        recipe,
        seed,
        first_case,
        cases,
        strategies,
        fields,
        mode,
        live,
        allow_malformed_live,
        destination,
        timeout_ms,
        rate,
        max_cases,
        max_total_bytes,
        max_field_bytes,
        max_list_items,
        max_shrink_steps,
        max_duration_ms,
        route,
        limits,
        policy,
    } = arguments;
    let targets = fields
        .into_iter()
        .map(|field| {
            field
                .parse::<core::fuzz::Target>()
                .map_err(|source| CliError::new(2, source.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let queue_limits = limits.into_limits();
    let request = core::fuzz::Request {
        seed,
        first_case,
        cases,
        strategies: strategies.into_iter().map(Into::into).collect(),
        targets,
        build: core::build::Options {
            mode: mode.into(),
            max_packet_size: queue_limits.snap_length,
            ..core::build::Options::default()
        },
        limits: core::fuzz::Limits {
            max_cases,
            max_packet_bytes: queue_limits.snap_length,
            max_total_bytes,
            max_field_bytes,
            max_list_items,
            max_shrink_steps,
            max_evidence_frames: queue_limits.max_frames,
            max_evidence_bytes: queue_limits.max_bytes,
            max_duration: Duration::from_millis(max_duration_ms),
        },
    };
    request.validate().map_err(CliError::classified)?;
    let prepared_live = if live {
        let live_options = packetcraftr::fuzz::LiveOptions {
            timeout: Duration::from_millis(timeout_ms),
            cases_per_second: rate,
            destination,
            allow_malformed_live,
        }
        .validate()
        .map_err(fuzz_cli_error)?;
        let policy = policy.into_policy();
        policy.validate().map_err(CliError::classified)?;
        validate_live_interface_selector("fuzz", route.interface.as_deref())?;
        let exchange = workflow_exchange_options(
            packetcraftr::send::Options {
                destination,
                plan: net::route::Options {
                    link_mode: route.link_mode.into(),
                    interface: None,
                    preferred_source: route.source,
                },
                build: request.build.clone(),
                allow_permissive_live: allow_malformed_live,
            },
            Duration::from_millis(timeout_ms),
            1,
            queue_limits,
        )?;
        Some((live_options, policy, exchange))
    } else {
        None
    };
    let registry = default_registry_arc()?;
    let packet = read_recipe(recipe, &registry)?;

    let (result, diagnostics, stats) = if let Some((live_options, policy, exchange)) = prepared_live
    {
        let mut executor = CliFuzzExecutor {
            client: system_client(Arc::clone(&registry), policy.clone()),
            exchange,
            interface: DeferredInterface::new(route.interface),
        };
        let mut authorizer = packetcraftr::fuzz::PolicyAuthorizer::new(&policy);
        let mut clock = packetcraftr::clock::SystemClock;
        let result = packetcraftr::fuzz::run(
            &request,
            live_options,
            packet,
            registry,
            &mut authorizer,
            &mut executor,
            &mut clock,
        )
        .map_err(fuzz_cli_error)?;
        output::fuzz::Result::try_from_live(result).map_err(CliError::classified)?
    } else {
        // This branch intentionally never validates or resolves the live
        // interface and never constructs a native client.
        let result = core::fuzz::run(&request, packet, registry).map_err(CliError::classified)?;
        output::fuzz::Result::try_from_offline(result).map_err(CliError::classified)?
    };
    match output {
        output::contract::Format::Text => render_fuzz_text(result, diagnostics, stats),
        output::contract::Format::Json => {
            emit_aggregate_with_stats(output::contract::Command::Fuzz, result, diagnostics, stats)
        }
        output::contract::Format::Ndjson => render_fuzz_stream(result, diagnostics, stats),
        _ => unreachable!("fuzz format is checked before command dispatch"),
    }
}

pub(crate) fn fuzz_cli_error(error: packetcraftr::fuzz::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
