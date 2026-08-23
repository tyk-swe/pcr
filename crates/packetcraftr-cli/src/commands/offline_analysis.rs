// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, bounded setup for offline analysis commands.

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    analysis,
    core::{filter::Filter, registry::Registry},
};

use super::super::command_options::OfflineLimitsArgs;
use super::super::filtering::{self, Capabilities};
use super::super::input::validate_capture_stream_limits;
use super::registry;
use packetcraftr::BoundaryError;

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
) -> Result<Prepared, BoundaryError> {
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
    limits.validate().map_err(BoundaryError::from_error)?;

    Ok(Prepared {
        registry,
        filter,
        limits,
    })
}
