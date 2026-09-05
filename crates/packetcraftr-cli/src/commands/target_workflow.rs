// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The shell shared by the target-probing commands: `scan`, `traceroute`, and
//! `dns`.
//!
//! All three take the same route, capture, and policy arguments, compose the
//! same executor, and render the same three ways: one text report, one
//! aggregate JSON document, or one NDJSON record per event followed by a
//! completion record. Only the workflow types and the per-command text report
//! differ, so those are what [`TargetWorkflow`] carries.

use packetcraftr::output::contract::Format;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{core, netio as net, output};
use serde::Serialize;

use super::execution::Executor;
use super::registry;
use crate::command_options::{HostnamePolicyArgs, RouteSelectionArgs};
use crate::errors::CliError;
use crate::rendering::{StreamEncoder, emit_aggregate_with_stats};
use crate::system::{InterfaceSelector, client, exchange};

/// One probing workflow: the library entry points and the output types they
/// convert into.
pub(super) trait TargetWorkflow {
    /// The command this workflow reports as.
    const COMMAND: output::contract::Command;

    type Request;
    type Event;
    type Summary;
    /// The aggregate document, for text and JSON.
    type Document: Serialize;
    /// One NDJSON record, for both events and the completion.
    type Record: Serialize;

    /// Runs to completion, then converts the result into its output document.
    fn execute(
        request: &Self::Request,
        authorizer: &mut impl packetcraftr::target::Authorizer,
        registry: &core::registry::Registry,
        executor: &mut Executor,
        clock: &mut impl packetcraftr::clock::Clock,
    ) -> Result<Document<Self::Document>, CliError>;

    /// Runs with events, emitting each one as it becomes final.
    fn stream(
        request: &Self::Request,
        authorizer: &mut impl packetcraftr::target::Authorizer,
        registry: &core::registry::Registry,
        executor: &mut Executor,
        clock: &mut impl packetcraftr::clock::Clock,
        runtime: &packetcraftr::progress::Runtime,
        stream: &StreamEncoder,
    ) -> Result<(), CliError>;

    /// The human report for one completed run.
    fn render_text(document: Document<Self::Document>) -> Result<(), CliError>;

    fn convert_event(
        event: Self::Event,
    ) -> Result<(Self::Record, Vec<core::diagnostic::Diagnostic>), CliError>;

    fn convert_complete(
        summary: Self::Summary,
    ) -> Result<
        (
            Self::Record,
            Vec<core::diagnostic::Diagnostic>,
            output::envelope::Stats,
        ),
        CliError,
    >;

    /// Writes one event as an NDJSON record.
    fn emit_event(event: Self::Event, stream: &StreamEncoder) -> Result<(), CliError> {
        let (record, diagnostics) = Self::convert_event(event)?;
        Ok(stream.emit_data(record, diagnostics)?)
    }

    /// Writes the terminal completion record.
    fn emit_complete(summary: Self::Summary, stream: &StreamEncoder) -> Result<(), CliError> {
        let (record, diagnostics, stats) = Self::convert_complete(summary)?;
        Ok(stream.complete_with_stats(record, diagnostics, stats)?)
    }
}

/// One completed run: the document plus the diagnostics and statistics that
/// travel with it in every format.
pub(super) struct Document<T> {
    pub(super) result: T,
    pub(super) diagnostics: Vec<core::diagnostic::Diagnostic>,
    pub(super) stats: output::envelope::Stats,
}

impl<T> Document<T> {
    pub(super) const fn new(
        result: T,
        diagnostics: Vec<core::diagnostic::Diagnostic>,
        stats: output::envelope::Stats,
    ) -> Self {
        Self {
            result,
            diagnostics,
            stats,
        }
    }
}

/// Runs one prepared workflow and renders it in the requested format.
pub(super) fn run<W: TargetWorkflow>(
    request: &W::Request,
    providers: &mut TargetProviders,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let resolver = packetcraftr::target::SystemResolver;
    let mut authorizer = packetcraftr::target::PolicyAuthorizer::new(&providers.policy, &resolver);
    let mut clock = packetcraftr::clock::SystemClock;
    match format {
        Format::Text | Format::Json => {
            let document = W::execute(
                request,
                &mut authorizer,
                &providers.registry,
                &mut providers.executor,
                &mut clock,
            )?;
            if format == Format::Text {
                W::render_text(document)
            } else {
                emit_aggregate_with_stats(
                    W::COMMAND,
                    document.result,
                    document.diagnostics,
                    document.stats,
                )
            }
        }
        Format::Ndjson => W::stream(
            request,
            &mut authorizer,
            &providers.registry,
            &mut providers.executor,
            &mut clock,
            &providers.runtime,
            stream,
        ),
        _ => unreachable!("command dispatch validated the output format"),
    }
}

/// The providers the three commands compose identically once their request is
/// built.
pub(super) struct TargetProviders {
    policy: packetcraftr::policy::Policy,
    pub(super) registry: Arc<core::registry::Registry>,
    executor: Executor,
    /// Admits the one callback worker NDJSON streaming publishes through.
    runtime: packetcraftr::progress::Runtime,
}

/// Validates the policy and interface selector, then binds an executor to the
/// requested route.
///
/// `max_template_packets` is how many packets one exchange may hold: one query
/// for `dns`, one batch for `scan`, one attempt per hop for `traceroute`.
pub(super) fn prepare(
    route: RouteSelectionArgs,
    policy: HostnamePolicyArgs,
    timeout: Duration,
    max_template_packets: usize,
    queue_limits: net::capture::Limits,
) -> Result<TargetProviders, CliError> {
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let interface = InterfaceSelector::parse_optional(route.interface.as_deref())?;
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
        timeout,
        max_template_packets,
        queue_limits,
    )?;
    let executor = Executor {
        client: client(Arc::clone(&registry), policy.clone()),
        exchange,
        interface,
    };
    Ok(TargetProviders {
        policy,
        registry,
        executor,
        runtime: packetcraftr::progress::Runtime::default(),
    })
}
