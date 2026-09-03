// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, bounded setup for offline analysis commands.

use packetcraftr::core::error::Kind;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    analysis,
    core::{self, filter::Filter, registry::Registry},
};

use analysis::{StreamRef, StreamTransport};

use super::registry_with_tls_ports;
use crate::command_options::OfflineLimitsArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::validate_capture_stream_limits;
use crate::rendering::StreamEncoder;

/// Validated, I/O-free analysis state.
pub(super) struct AnalysisSetup {
    pub(super) registry: Arc<Registry>,
    pub(super) filter: Option<Filter>,
    pub(super) ip_overlap: analysis::reassembly::ip::OverlapPolicy,
    pub(super) limits: analysis::Limits,
}

impl AnalysisSetup {
    /// Analysis options from every prepared analysis-wide setting; commands
    /// choose only whether the run drives TCP reassembly.
    pub(super) fn options(&self, tcp_events: bool) -> analysis::Options<'_> {
        analysis::Options {
            filter: self.filter.as_ref(),
            tcp_events,
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
) -> Result<AnalysisSetup, CliError> {
    prepare_with_tls_ports(limits, filter_source, &[])
}

/// [`prepare`], with extra TCP ports dissected as TLS.
///
/// The registry is immutable once built, so the extra bindings must be
/// supplied here.
pub(super) fn prepare_with_tls_ports(
    limits: OfflineLimitsArgs,
    filter_source: Option<&str>,
    tls_ports: &[u16],
) -> Result<AnalysisSetup, CliError> {
    let capture = limits.capture;
    let ip_overlap = limits.ip_overlap.into();
    validate_capture_stream_limits(capture)?;
    let registry = registry_with_tls_ports(tls_ports)?;
    let filter = filter_source
        .map(|source| filtering::compile(source, &registry, Capabilities::stream_capable()))
        .transpose()?;
    let limits = analysis::Limits {
        max_frames: capture.max_frames,
        max_bytes: capture.max_bytes,
        max_frame_bytes: capture.reader.max_frame_bytes,
        max_flows: limits.max_flows,
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
        ip_overlap,
        limits,
    })
}

/// The items an aggregate JSON document holds in memory before it can be
/// written, under a finite ceiling.
///
/// Only the aggregate JSON renderer fills one; text and NDJSON write each item
/// as it completes and retain nothing.
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

    /// Retains one item, or counts it as omitted once the ceiling is reached.
    pub(super) fn push(&mut self, item: T) {
        if self.items.len() >= self.maximum {
            self.omitted = self.omitted.saturating_add(1);
            return;
        }
        self.items.push(item);
    }

    /// How many items the ceiling kept out of the document.
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

/// Sink for IP reassembly lifecycle events, which only the NDJSON stream
/// carries. The other formats fold the same information into their terminal
/// `ip_reassembly` report, so they pass `None` and the events are dropped.
pub(super) fn ip_event_sink(
    stream: Option<StreamEncoder>,
) -> impl FnMut(analysis::IpEventRecord) -> Result<(), packetcraftr::BoundaryError> {
    move |event| {
        if let Some(stream) = &stream {
            stream
                .emit_data(
                    packetcraftr::output::reassembly::Event::from(event),
                    Vec::new(),
                )
                .map_err(|error| CliError::from(error).into_boundary_error())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn retention_counts_what_the_ceiling_kept_out() {
        let mut retained = Retained::new(2);
        for value in 0..5_u8 {
            retained.push(value);
        }
        assert_eq!(retained.omitted(), 3);
        assert_eq!(retained.into_items(), vec![0, 1]);

        let mut empty = Retained::new(0);
        empty.push(1_u8);
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
