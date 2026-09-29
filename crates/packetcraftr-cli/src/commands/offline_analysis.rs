// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::analysis;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::registry::Registry;

use std::path::Path;

use analysis::StreamRef;
use packetcraftr_core::error::Kind;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::output::contract::ToolFormat;
use crate::rendering::{EventOutput, StreamEncoder, ip_event_sink};

pub(super) struct AnalysisSetup {
    pub(super) registry: Arc<Registry>,
    pub(super) filter: Option<Filter>,
    pub(super) time_bounds: Option<packetcraftr_core::frame::TimeBounds>,
    pub(super) ip_overlap: analysis::reassembly::ip::OverlapPolicy,
    pub(super) limits: analysis::Limits,
}

impl AnalysisSetup {
    pub(super) fn options(&self) -> analysis::Options<'_> {
        analysis::Options {
            plan: analysis::Plan::default(),
            deadline: crate::invocation::deadline(),
            track_sources: false,
            cancellation: Some(crate::cancellation::signal().clone()),
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
    limits: OfflineLimitsArgs,
    filter_source: Option<&str>,
    decode: &DecodeArgs,
) -> Result<AnalysisSetup, CliError> {
    let capture = limits.capture;
    let duration = limits.duration;
    let ip_overlap = limits.ip_overlap.into();
    let time_bounds = limits.epoch.resolve()?;
    capture.validate()?;
    let registry = decode.registry()?;
    let filter = filter_source
        .map(|source| filtering::compile(source, &registry, Capabilities::stream_capable()))
        .transpose()?;
    let limits = analysis::Limits {
        max_provenance_bytes: limits.max_provenance_bytes,
        max_frames: capture.max_frames,
        max_bytes: capture.max_bytes,
        max_frame_bytes: capture.reader.max_frame_bytes,
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
    duration.within_ceiling(|value| {
        CliError::classified(analysis::Error::InvalidLimit {
            field: "max_duration",
            value,
            reason: analysis::Constraint::AtMostOneHour,
        })
    })?;

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
    pub(super) output_bytes: usize,
    pub(super) selector: Option<StreamRef>,
}

pub(super) fn inspect<C: analysis::Collector>(
    inspection: Inspection<'_>,
    collector: C,
    format: ToolFormat,
    stream: &StreamEncoder,
    mut publish: impl FnMut(&mut EventOutput<'_>, C::Event) -> Result<(), CliError>,
) -> Result<analysis::Outcome<C>, CliError> {
    let Inspection {
        path,
        limits,
        decode,
        output_bytes,
        selector,
    } = inspection;
    let setup = prepare(limits, None, decode)?;
    // The session raises the TCP/source-tracking flags from the collector's declared needs.
    let session =
        analysis::Session::new(setup.registry.clone(), setup.options(), collector, selector);
    let mut reader = crate::input::open_capture(path, limits.capture.reader)?;
    let mut output = EventOutput::new(format, stream, output_bytes);
    let outcome = session
        .run(&mut reader, ip_event_sink(format, stream), |event| {
            publish(&mut output, event).map_err(CliError::into_boundary_error)
        })
        .map_err(CliError::classified)?;
    if outcome.selected_absent() {
        return Err(CliError::new(Kind::Usage, "selected stream is not present"));
    }
    Ok(outcome)
}
