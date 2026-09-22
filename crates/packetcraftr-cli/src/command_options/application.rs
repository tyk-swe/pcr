// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use packetcraftr_core::analysis::application::Limits;
#[derive(Clone, Copy, Debug, clap::Args)]
pub(crate) struct ApplicationLimitsArgs {
    /// Distinct application messages the collector may count across all
    /// streams over the whole run.
    #[arg(long, default_value_t = Limits::default().max_messages)]
    pub(crate) max_application_messages: usize,
    /// Distinct transport streams the collector may track at once (TCP
    /// conversations; DNS also counts UDP flows).
    #[arg(long, default_value_t = Limits::default().max_streams)]
    pub(crate) max_application_streams: usize,
    /// Bytes buffered at once across all in-flight message parses (partial
    /// heads, body decoders, length prefixes).
    #[arg(long, default_value_t = Limits::default().max_buffer_bytes)]
    pub(crate) max_application_buffer_bytes: usize,
    /// Cumulative byte charge for retained and emitted evidence, including a
    /// conservative decoded-object expansion multiplier; bounds analysis
    /// state, not serialized output (see --max-application-output-bytes).
    #[arg(long, default_value_t = Limits::default().max_retained_bytes)]
    pub(crate) max_application_retained_bytes: usize,
    /// TCP sequence spans retained to attribute deliveries to physical source
    /// frames; HTTP also bounds one message's distinct source frames.
    #[arg(long, default_value_t = Limits::default().max_source_spans)]
    pub(crate) max_application_source_spans: usize,
    /// Total serialized message, transaction, and issue bytes, in every format.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub(crate) max_application_output_bytes: usize,
}
impl ApplicationLimitsArgs {
    pub(crate) fn core(self) -> Limits {
        Limits {
            max_messages: self.max_application_messages,
            max_streams: self.max_application_streams,
            max_buffer_bytes: self.max_application_buffer_bytes,
            max_retained_bytes: self.max_application_retained_bytes,
            max_source_spans: self.max_application_source_spans,
        }
    }
    pub(crate) fn validate_output(self) -> Result<(), CliError> {
        validate_output_bytes(self.max_application_output_bytes)
    }
}

/// The shared `--max-application-output-bytes` range every consumer enforces.
pub(crate) fn validate_output_bytes(value: usize) -> Result<(), CliError> {
    if value == 0 || value > 256 * 1024 * 1024 {
        return Err(CliError::new(
            packetcraftr_core::error::Kind::Cli,
            "--max-application-output-bytes must be in 1..=268435456",
        ));
    }
    Ok(())
}
