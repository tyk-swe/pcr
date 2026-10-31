// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::Bounded as _;
use crate::output::envelope::Published;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::analysis;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::registry::Registry;

use std::path::Path;

use analysis::{StreamRef, StreamTransport};
use packetcraftr_core::error::Kind;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs, Selector};
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::output::contract::{Command, Format};
use crate::rendering::{EventOutput, emit_published, ip_event_sink};

pub(super) struct AnalysisSetup {
    pub(super) registry: Arc<Registry>,
    pub(super) filter: Option<Filter>,
    pub(super) time_bounds: Option<packetcraftr_core::frame::TimeBounds>,
    pub(super) ip_overlap: analysis::reassembly::ip::OverlapPolicy,
    pub(super) limits: analysis::Limits,
}

impl AnalysisSetup {
    pub(super) fn options(
        &self,
        invocation: &crate::invocation::Invocation,
    ) -> analysis::Options<'_> {
        analysis::Options {
            plan: analysis::Plan::default(),
            deadline: invocation.deadline.clone(),
            track_sources: false,
            cancellation: Some(invocation.cancellation.clone()),
            filter: self.filter.as_ref(),
            stream: None,
            time_bounds: self.time_bounds,
            tcp_events: false,
            ip_overlap: self.ip_overlap,
            limits: self.limits.clone(),
        }
    }
}

pub(super) fn prepare(
    capture_limits: crate::command_options::OfflineCaptureLimits,
    limits: OfflineLimitsArgs,
    filter_source: Option<&str>,
    decode: &DecodeArgs,
) -> Result<AnalysisSetup, CliError> {
    let duration = limits.duration;
    let ip_overlap = limits.ip_overlap.into();
    let time_bounds = limits.epoch.resolve()?;
    let registry = decode.registry()?;
    let filter = filter_source
        .map(|source| filtering::compile(source, &registry, Capabilities::stream_capable()))
        .transpose()?;
    let limits = analysis::Limits {
        max_provenance_bytes: limits.max_provenance_bytes,
        max_frames: capture_limits.max_frames(),
        max_bytes: capture_limits.max_bytes(),
        max_frame_bytes: capture_limits.reader_bounds().max_frame_bytes,
        max_flows: limits.max_flows,
        max_scope_bytes: limits.max_scope_bytes,
        // Each conversation occupies one TCP reassembly flow per direction.
        tcp: analysis::reassembly::tcp::Limits {
            max_flows: limits.max_flows.saturating_mul(2),
            max_bytes_per_flow: limits.max_tcp_bytes_per_flow,
            max_aggregate_bytes: limits.max_tcp_reassembly_bytes,
            max_segments_per_flow: limits.max_tcp_segments_per_flow,
            idle_expiry: Duration::from_millis(limits.tcp_idle_expiry_ms),
        },
        ip: analysis::reassembly::ip::Limits {
            max_datagrams: limits.max_ip_datagrams,
            max_fragments_per_datagram: limits.max_ip_fragments_per_datagram,
            max_bytes_per_datagram: limits.max_ip_bytes_per_datagram,
            max_aggregate_bytes: limits.max_ip_reassembly_bytes,
            max_retained_outcomes: limits.max_ip_outcomes,
            idle_expiry: Duration::from_millis(limits.ip_idle_expiry_ms),
        },
        max_duration: duration.max_duration(),
    };
    limits.validate().map_err(CliError::classified)?;

    Ok(AnalysisSetup {
        registry,
        filter,
        time_bounds,
        ip_overlap,
        limits,
    })
}

pub(super) struct Inspection<'a> {
    pub(super) path: &'a Path,
    pub(super) limits: OfflineLimitsArgs,
    pub(super) decode: &'a DecodeArgs,
    pub(super) application: crate::command_options::ApplicationLimits,
    pub(super) selector: Option<StreamRef>,
}

pub(super) fn inspect<C: analysis::Collector>(
    invocation: &crate::invocation::Invocation,
    inspection: Inspection<'_>,
    collector: C,
    mut publish: impl FnMut(&mut EventOutput<'_>, C::Event) -> Result<(), CliError>,
) -> Result<analysis::Outcome<C>, CliError> {
    let Inspection {
        path,
        limits,
        decode,
        application,
        selector,
    } = inspection;
    let capture_limits = limits.capture.limits()?;
    let setup = prepare(capture_limits, limits, None, decode)?;
    // The session raises the TCP/source-tracking flags from the collector's declared needs.
    let session = analysis::Session::new(
        setup.registry.clone(),
        analysis::Options {
            stream: selector,
            ..setup.options(invocation)
        },
        collector,
    );
    let mut reader = crate::input::open_capture(invocation, path, capture_limits.reader_bounds())?;
    let mut output = EventOutput::new(invocation, application.max_output_bytes());
    let outcome = session
        .run(
            &mut reader,
            ip_event_sink(invocation.format, &invocation.output),
            |event| publish(&mut output, event).map_err(CliError::into_boundary_error),
        )
        .map_err(CliError::classified)?;
    if outcome.selected_absent() {
        return Err(CliError::new(Kind::Usage, "selected stream is not present"));
    }
    Ok(outcome)
}

pub(super) fn require_tcp_stream(
    stream: Option<&Selector<StreamRef>>,
    protocol: &str,
) -> Result<Option<StreamRef>, CliError> {
    let selector = stream.map(Selector::get).transpose()?;
    if selector.is_some_and(|selected| selected.transport != StreamTransport::Tcp) {
        return Err(CliError::new(
            Kind::Usage,
            format!("{protocol} inspection requires --stream tcp:INDEX"),
        ));
    }
    Ok(selector)
}

pub(super) fn complete_application<C, R>(
    invocation: &crate::invocation::Invocation,
    command: Command,
    complete: C,
    report: impl FnOnce(C) -> R,
    render: impl FnOnce(&crate::invocation::Invocation, &C) -> Result<(), CliError>,
) -> Result<(), CliError>
where
    C: serde::Serialize,
    R: serde::Serialize,
{
    match invocation.format {
        Format::Json => emit_published(
            invocation,
            command,
            Published::new(report(complete), Vec::new()),
        ),
        Format::Ndjson => invocation
            .output
            .complete_published(Published::new(complete, Vec::new()))
            .map_err(Into::into),
        Format::Text => render(invocation, &complete),
        other => other.unreachable(),
    }
}
