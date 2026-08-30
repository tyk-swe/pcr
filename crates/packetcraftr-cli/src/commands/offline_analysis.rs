// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, bounded setup for offline analysis commands.

use packetcraftr::core::error::Kind;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    analysis,
    core::{filter::Filter, registry::Registry},
};

use analysis::expert::StreamTransport;

use super::super::command_options::OfflineLimitsArgs;
use super::super::errors::CliError;
use super::super::filtering::{self, Capabilities};
use super::super::input::validate_capture_stream_limits;
use super::super::rendering::StreamEncoder;
use super::registry_with_tls_ports;

/// Validated, I/O-free analysis state.
pub(super) struct Prepared {
    pub(super) registry: Arc<Registry>,
    pub(super) filter: Option<Filter>,
    pub(super) ip_overlap: analysis::reassembly::ip::OverlapPolicy,
    pub(super) limits: analysis::Limits,
}

impl Prepared {
    /// Analysis options carrying every prepared analysis-wide setting, so a
    /// new knob needs no per-command plumbing. Commands choose only whether
    /// the run drives TCP reassembly.
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
) -> Result<Prepared, CliError> {
    prepare_with_tls_ports(limits, filter_source, &[])
}

/// [`prepare`], with extra TCP ports dissected as TLS.
///
/// The seam exists because the default registry is immutable once built, so a
/// command honouring `--tls-port` needs the extra bindings before the registry
/// is frozen rather than after.
pub(super) fn prepare_with_tls_ports(
    limits: OfflineLimitsArgs,
    filter_source: Option<&str>,
    tls_ports: &[u16],
) -> Result<Prepared, CliError> {
    let capture = limits.capture;
    let ip_overlap = limits.ip_overlap.into();
    validate_capture_stream_limits(
        capture.max_frames,
        capture.max_bytes,
        capture.max_frame_bytes,
        capture.max_interfaces,
    )?;
    let registry = registry_with_tls_ports(tls_ports)?;
    let filter = filter_source
        .map(|source| filtering::compile(source, &registry, Capabilities::stream_capable()))
        .transpose()?;
    let limits = analysis::Limits {
        max_frames: capture.max_frames,
        max_bytes: capture.max_bytes,
        max_frame_bytes: capture.max_frame_bytes,
        max_flows: limits.max_flows,
        max_ip_datagrams: limits.max_ip_datagrams,
        max_ip_fragments_per_datagram: limits.max_ip_fragments_per_datagram,
        max_ip_bytes_per_datagram: limits.max_ip_bytes_per_datagram,
        max_ip_reassembly_bytes: limits.max_ip_reassembly_bytes,
        max_ip_outcomes: limits.max_ip_outcomes,
        ip_idle_expiry: Duration::from_millis(limits.ip_idle_expiry_ms),
        max_duration: Duration::from_millis(limits.max_duration_ms),
    };
    limits.validate().map_err(CliError::classified)?;

    Ok(Prepared {
        registry,
        filter,
        ip_overlap,
        limits,
    })
}

/// A parsed `--stream` conversation spec.
///
/// Parsing admits both transports so each command states its own
/// restriction: `follow` follows either, while a TCP-only command rejects a
/// `udp:` selector with a message that says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamSelector {
    pub(crate) transport: StreamTransport,
    pub(crate) index: u64,
}

/// Parses a `tcp:INDEX` or `udp:INDEX` conversation spec.
pub(crate) fn parse_stream_selector(spec: &str) -> Result<StreamSelector, CliError> {
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
    Ok(StreamSelector { transport, index })
}

/// Sink for IP reassembly lifecycle events, which only the NDJSON stream
/// carries. The other formats fold the same information into their terminal
/// `ip_reassembly` report, so they drop the per-event record here.
pub(super) fn ip_event_sink(
    ndjson: bool,
    stream: StreamEncoder,
) -> impl FnMut(analysis::IpEventRecord) -> Result<(), packetcraftr::BoundaryError> {
    move |event| {
        if ndjson {
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
