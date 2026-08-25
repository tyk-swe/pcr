// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, bounded setup for offline analysis commands.

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
use super::registry;

/// Validated, I/O-free analysis state.
pub(super) struct Prepared {
    pub(super) registry: Arc<Registry>,
    pub(super) filter: Option<Filter>,
    pub(super) limits: analysis::Limits,
}

/// Validates capture bounds, prepares registry/filter state, then validates
/// analysis bounds.
pub(super) fn prepare(
    limits: OfflineLimitsArgs,
    filter_source: Option<&str>,
) -> Result<Prepared, CliError> {
    let capture = limits.capture;
    validate_capture_stream_limits(
        capture.max_frames,
        capture.max_bytes,
        capture.max_frame_bytes,
        capture.max_interfaces,
    )?;
    let registry = registry()?;
    let filter = filter_source
        .map(|source| filtering::compile(source, &registry, Capabilities::stream_capable()))
        .transpose()?;
    let limits = analysis::Limits {
        max_frames: capture.max_frames,
        max_bytes: capture.max_bytes,
        max_frame_bytes: capture.max_frame_bytes,
        max_flows: limits.max_flows,
        max_duration: Duration::from_millis(limits.max_duration_ms),
    };
    limits.validate().map_err(CliError::classified)?;

    Ok(Prepared {
        registry,
        filter,
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
            2,
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
