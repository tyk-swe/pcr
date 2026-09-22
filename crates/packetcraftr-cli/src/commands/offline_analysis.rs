// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, bounded setup for offline analysis commands.

use packetcraftr_core::error::Kind;

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_core::analysis;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::registry::Registry;

use analysis::{StreamRef, StreamTransport};

use crate::command_options::{CaptureReaderBoundsArgs, DecodeArgs, OfflineLimitsArgs};
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{open_capture, validate_capture_stream_limits};
use crate::rendering::StreamEncoder;

/// A prepared session and the capture it observes.
type OpenSession<'a, C> = (
    analysis::pcap::Reader<Box<dyn Read>>,
    analysis::Session<'a, C>,
);

/// Validated, I/O-free analysis state.
pub(super) struct AnalysisSetup {
    registry: Arc<Registry>,
    filter: Option<Filter>,
    time_bounds: Option<packetcraftr_core::frame::TimeBounds>,
    ip_overlap: analysis::reassembly::ip::OverlapPolicy,
    limits: analysis::Limits,
}

impl AnalysisSetup {
    /// Opens the bounded capture and builds its session from this preparation.
    /// The prepared filter stays borrowed until the pass completes.
    pub(super) fn open_session<C: analysis::Collector>(
        &self,
        path: &Path,
        reader_bounds: CaptureReaderBoundsArgs,
        collector: C,
        selector: Option<StreamRef>,
    ) -> Result<OpenSession<'_, C>, CliError> {
        let session =
            analysis::Session::new(self.registry.clone(), self.options(), collector, selector);
        let reader = open_capture(path, reader_bounds)?;
        Ok((reader, session))
    }

    /// The prepared protocol registry for consumers such as TLS rendering.
    pub(super) fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Non-session analysis operations also use the prepared registry.
    pub(super) fn shared_registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    /// The prepared frame filter used by export's multi-selector planner.
    pub(super) fn filter(&self) -> Option<&Filter> {
        self.filter.as_ref()
    }

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
        max_tcp_bytes_per_flow: limits.max_tcp_bytes_per_flow,
        max_tcp_reassembly_bytes: limits.max_tcp_reassembly_bytes,
        max_tcp_segments_per_flow: limits.max_tcp_segments_per_flow,
        tcp_idle_expiry: Duration::from_millis(limits.tcp_idle_expiry_ms),
        max_ip_datagrams: limits.max_ip_datagrams,
        max_ip_fragments_per_datagram: limits.max_ip_fragments_per_datagram,
        max_ip_bytes_per_datagram: limits.max_ip_bytes_per_datagram,
        max_ip_reassembly_bytes: limits.max_ip_reassembly_bytes,
        max_ip_outcomes: limits.max_ip_outcomes,
        ip_idle_expiry: Duration::from_millis(limits.ip_idle_expiry_ms),
        max_duration: Duration::from_millis(limits.max_duration_ms),
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

/// Parses a `tcp:INDEX` or `udp:INDEX` conversation spec.
///
/// Parsing admits both transports so each command states its own
/// restriction: `follow` follows either, while a TCP-only command rejects a
/// `udp:` selector with a message that says so.
pub(crate) fn parse_stream_selector(spec: &str) -> Result<StreamRef, CliError> {
    let invalid = || {
        CliError::new(
            Kind::Cli,
            format!("invalid --stream '{spec}': expected tcp:INDEX or udp:INDEX"),
        )
    };
    let (transport, index) = spec.split_once(':').ok_or_else(invalid)?;
    let transport = match transport {
        "tcp" => StreamTransport::Tcp,
        "udp" => StreamTransport::Udp,
        _ => return Err(invalid()),
    };
    let index = index.parse::<u64>().map_err(|_| invalid())?;
    Ok(StreamRef { transport, index })
}

/// Maps the session's typed absence to the one offline-analysis CLI error.
/// Call after the terminal drain, except for follow, whose verdict must
/// precede collector finish and publication of any staged output files.
pub(super) fn require_selected_stream(
    selection: Option<analysis::StreamSelection>,
) -> Result<(), CliError> {
    if let Some(analysis::StreamSelection::Absent(stream)) = selection {
        return Err(CliError::new(
            Kind::Cli,
            format!(
                "--stream {}:{} is not present",
                stream.transport, stream.index
            ),
        ));
    }
    Ok(())
}

/// Sink for IP reassembly lifecycle events, which only the NDJSON stream
/// carries. The other formats fold the same information into their terminal
/// `ip_reassembly` report, so a non-NDJSON `format` drops every event.
pub(super) fn ip_event_sink<F>(
    format: F,
    stream: &StreamEncoder,
) -> impl FnMut(analysis::IpEventRecord) -> Result<(), packetcraftr_core::error::BoundaryError>
where
    F: Into<packetcraftr_cli::output::contract::Format>,
{
    let stream = (format.into() == packetcraftr_cli::output::contract::Format::Ndjson)
        .then(|| stream.clone());
    move |event| {
        if let Some(stream) = &stream {
            stream
                .emit_data(
                    packetcraftr_cli::output::reassembly::Event::from(event),
                    Vec::new(),
                )
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
