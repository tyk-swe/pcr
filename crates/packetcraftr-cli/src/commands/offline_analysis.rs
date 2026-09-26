// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, bounded setup for offline analysis commands.

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_core::analysis;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::registry::Registry;

use std::path::Path;

use analysis::StreamRef;
use packetcraftr_core::error::Kind;

use super::application_output::EventOutput;
use crate::command_options::{ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs};
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::validate_capture_stream_limits;
use crate::output::contract::ToolFormat;
use crate::rendering::StreamEncoder;

/// Validated, I/O-free analysis state.
pub(super) struct AnalysisSetup {
    pub(super) registry: Arc<Registry>,
    pub(super) filter: Option<Filter>,
    pub(super) time_bounds: Option<packetcraftr_core::frame::TimeBounds>,
    pub(super) ip_overlap: analysis::reassembly::ip::OverlapPolicy,
    pub(super) limits: analysis::Limits,
}

impl AnalysisSetup {
    /// Analysis options from every prepared analysis-wide setting, with every
    /// optional stage at its base setting. Commands that drive a collector
    /// through [`analysis::Session`] declare their needs there instead; the
    /// session raises `plan`, `tcp_events`, and `track_sources` to cover them.
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

/// Validates capture bounds, prepares registry/filter state, then validates
/// analysis bounds.
pub(super) fn prepare(
    limits: OfflineLimitsArgs,
    filter_source: Option<&str>,
    decode: &DecodeArgs,
) -> Result<AnalysisSetup, CliError> {
    let capture = limits.capture;
    let duration = limits.duration;
    let ip_overlap = limits.ip_overlap.into();
    let time_bounds = limits.epoch.resolve()?;
    validate_capture_stream_limits(capture)?;
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

/// What one application-layer inspection (`dns-read`, `http`) reads: the
/// capture, its bounds and decoding, and the one conversation it may keep.
pub(super) struct Inspection<'a> {
    pub(super) path: &'a Path,
    pub(super) limits: OfflineLimitsArgs,
    pub(super) decode: &'a DecodeArgs,
    pub(super) application: ApplicationLimitsArgs,
    pub(super) selector: Option<StreamRef>,
}

/// Runs one collector over a capture file, publishing each event through
/// `publish` under the shared `--max-application-output-bytes` budget, and
/// fails when a selected conversation is absent.
///
/// The selector narrows the pass to its conversation; IP reassembly events
/// reach the NDJSON stream only.
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
        application,
        selector,
    } = inspection;
    let setup = prepare(limits, None, decode)?;
    // The session narrows the plan and raises the TCP/source-tracking flags
    // from the collector's declared needs.
    let session =
        analysis::Session::new(setup.registry.clone(), setup.options(), collector, selector);
    let mut reader = crate::input::open_capture(path, limits.capture.reader)?;
    let mut output = EventOutput::new(format, stream, application.max_application_output_bytes);
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

/// Retains output items under a finite ceiling while counting omissions.
pub(super) struct Retained<T> {
    maximum: usize,
    items: Vec<T>,
    omitted: u64,
}

impl<T> Retained<T> {
    pub(super) const fn new(maximum: usize) -> Self {
        Self {
            maximum,
            items: Vec::new(),
            omitted: 0,
        }
    }

    /// Converts and retains one item only while capacity remains; otherwise
    /// counts it as omitted without calling the conversion.
    pub(super) fn push(&mut self, convert: impl FnOnce() -> T) {
        if self.items.len() >= self.maximum {
            self.omitted = self.omitted.saturating_add(1);
            return;
        }
        self.items.push(convert());
    }

    pub(super) const fn omitted(&self) -> u64 {
        self.omitted
    }

    pub(super) fn into_items(self) -> Vec<T> {
        self.items
    }
}

/// The one diagnostic a document that left items out carries, so a truncated
/// document never looks complete.
pub(super) fn omitted_diagnostic(
    code: &'static str,
    subject: &str,
    omitted: u64,
    ceiling: &str,
) -> Vec<core::diagnostic::Diagnostic> {
    if omitted == 0 {
        return Vec::new();
    }
    vec![core::diagnostic::Diagnostic::warning(
        code,
        format!("{omitted} {subject} omitted from this document by the {ceiling} ceiling"),
    )]
}

/// Sink for IP reassembly lifecycle events, which only the NDJSON stream
/// carries. The other formats fold the same information into their terminal
/// `ip_reassembly` report, so a non-NDJSON `format` drops every event.
pub(super) fn ip_event_sink<F>(
    format: F,
    stream: &StreamEncoder,
) -> impl FnMut(analysis::IpEventRecord) -> Result<(), packetcraftr_core::error::BoundaryError>
where
    F: Into<crate::output::contract::Format>,
{
    let stream = (format.into() == crate::output::contract::Format::Ndjson).then(|| stream.clone());
    move |event| {
        if let Some(stream) = &stream {
            stream
                .emit_data(crate::output::reassembly::Event::from(event), Vec::new())
                .map_err(|error| CliError::from(error).into_boundary_error())?;
        }
        Ok(())
    }
}

pub(super) fn render_scope(scope: &analysis::scope::Definition) -> Result<(), CliError> {
    crate::rendering::write_stdout_line(format_args!(
        "scope {}: interface {:?}, encapsulation {:?}",
        scope.id.get(),
        scope.interface,
        scope.encapsulation
    ))
}

pub(super) fn render_clock(clock: &analysis::ClockReport) -> Result<(), CliError> {
    crate::rendering::write_stdout_line(format_args!(
        "capture clock: {} regressing frame(s), largest rollback {:?}, largest forward step {:?} at frame {:?}; expiry follows the high-water mark",
        clock.regressions,
        clock.max_regression,
        clock.max_forward_step,
        clock.max_forward_step_frame,
    ))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn retention_skips_conversion_for_items_the_ceiling_keeps_out() {
        let mut conversions = 0;
        let mut retained = Retained::new(2);
        for value in 0..5_u8 {
            retained.push(|| {
                conversions += 1;
                value
            });
        }
        assert_eq!(conversions, 2);
        assert_eq!(retained.omitted(), 3);
        assert_eq!(retained.into_items(), vec![0, 1]);

        let mut empty = Retained::new(0);
        empty.push(|| {
            conversions += 1;
            1_u8
        });
        assert_eq!(conversions, 2);
        assert_eq!(empty.omitted(), 1);
        assert!(empty.into_items().is_empty());
    }

    #[test]
    fn a_complete_document_carries_no_omission_diagnostic() {
        assert!(
            omitted_diagnostic("expert.findings_omitted", "finding(s)", 0, "--max-frames")
                .is_empty()
        );

        let diagnostics =
            omitted_diagnostic("expert.findings_omitted", "finding(s)", 4, "--max-frames");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "expert.findings_omitted");
        assert_eq!(
            diagnostics[0].message,
            "4 finding(s) omitted from this document by the --max-frames ceiling",
        );
    }
}
