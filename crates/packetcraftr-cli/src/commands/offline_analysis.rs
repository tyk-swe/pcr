// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, bounded setup for offline analysis commands.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    analysis,
    capture::{Reader, ReaderOptions},
    packet::{filter::Filter, registry::Registry},
};

use super::super::arguments::{OfflineAnalysisLimits, OfflineCaptureLimits};
use super::super::errors::{CliError, analysis_cli_error};
use super::super::filtering::{self, Capabilities};
use super::super::input::validate_capture_stream_limits;
use super::super::runtime::default_registry_arc;

/// Validated, I/O-free analysis state.
pub(super) struct PreparedOfflineAnalysis {
    pub(super) registry: Arc<Registry>,
    pub(super) filter: Option<Filter>,
    pub(super) limits: analysis::Limits,
}

/// Validates finite bounds and compiles the optional stream-aware filter.
///
/// The ordering here is part of the CLI contract: capture bounds precede
/// registry/filter preparation, which precedes analysis bounds.
pub(super) fn prepare_offline_analysis(
    limits: OfflineAnalysisLimits,
    filter_source: Option<&str>,
) -> Result<PreparedOfflineAnalysis, CliError> {
    let capture = limits.capture;
    validate_capture_stream_limits(
        capture.max_frames,
        capture.max_bytes,
        capture.max_frame_bytes,
        capture.max_interfaces,
    )?;
    let registry = default_registry_arc()?;
    let filter = match filter_source {
        Some(source) => Some(filtering::compile(
            source,
            &registry,
            Capabilities::stream_capable(),
        )?),
        None => None,
    };
    let limits = analysis::Limits {
        max_frames: capture.max_frames,
        max_bytes: capture.max_bytes,
        max_frame_bytes: capture.max_frame_bytes,
        max_flows: limits.max_flows,
        max_duration: Duration::from_millis(limits.max_duration_ms),
    };
    limits.validate().map_err(analysis_cli_error)?;

    Ok(PreparedOfflineAnalysis {
        registry,
        filter,
        limits,
    })
}

/// Opens a prepared command's reader without changing validation precedence.
pub(super) fn open_offline_reader(
    path: &Path,
    limits: OfflineCaptureLimits,
) -> Result<Reader<File>, CliError> {
    let file = File::open(path)
        .map_err(|source| CliError::new(5, format!("open {} failed: {source}", path.display())))?;
    Reader::with_options(
        file,
        ReaderOptions {
            max_size: limits.max_frame_bytes,
            max_interfaces_per_section: limits.max_interfaces,
            ..ReaderOptions::default()
        },
    )
    .map_err(CliError::classified)
}
