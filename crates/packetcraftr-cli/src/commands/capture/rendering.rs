// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `capture`'s terminal summary in every format.

use crate::errors::CliError;
use crate::output::{
    self,
    contract::{CaptureFormat, Command},
};
use crate::rendering::{
    StreamEncoder, document_spelling, emit_aggregate_with_stats, render_diagnostics_stderr,
    render_diagnostics_text, write_stdout_line, write_summary_line,
};
use packetcraftr::Stats;

pub(super) fn render_complete(
    format: CaptureFormat,
    summary: &output::capture::Summary,
    stats: &Stats,
    diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    match format {
        CaptureFormat::Json => {
            emit_aggregate_with_stats(Command::Capture, summary, diagnostics, stats.clone())
        }
        CaptureFormat::Ndjson => stream
            .complete_with_stats(summary, diagnostics, stats.clone())
            .map_err(Into::into),
        CaptureFormat::Text => {
            write_summary_line(format_args!(
                "captured {} frames ({} emitted), {} bytes across {} interfaces; stopped for {}",
                stats.packets_attempted,
                stats.packets_completed,
                stats.bytes,
                summary.sources.len(),
                document_spelling(&summary.stop_reason)
            ))?;
            for source in &summary.sources {
                if let Some(settings) = &source.capture_settings {
                    write_stdout_line(format_args!(
                        "  source {} ({}): buffer_size {} timestamp_source {} timestamp_precision {}",
                        source.capture_id,
                        source.native_interface.name,
                        realized_text(&settings.buffer_size),
                        realized_text(&settings.timestamp_source),
                        realized_text(&settings.timestamp_precision),
                    ))?;
                }
            }
            if let Some(files) = &summary.files {
                for file in &files.files {
                    write_stdout_line(format_args!(
                        "  {}: {} frames, {} capture bytes, finalized={}",
                        file.path, file.frames, file.capture_bytes, file.finalized
                    ))?;
                }
                write_stdout_line(format_args!(
                    "  retention={}, retired files={}, retired frames={}",
                    document_spelling(&files.retention),
                    files.discarded_files,
                    files.discarded_frames
                ))?;
            }
            render_diagnostics_text(&diagnostics)
        }
        _ => render_diagnostics_stderr(&diagnostics),
    }
}

/// `requested/applied/effective` in one parenthesized triplet; `default` marks
/// an unset request, `-` a setting never applied, and `unknown` a value the
/// backend cannot confirm.
fn realized_text<T: std::fmt::Display>(
    realized: &packetcraftr_netio::capture::Realized<T>,
) -> String {
    fn field<T: std::fmt::Display>(value: &Option<T>, none: &str) -> String {
        value
            .as_ref()
            .map_or_else(|| none.to_owned(), ToString::to_string)
    }
    format!(
        "(requested={} applied={} effective={})",
        field(&realized.requested, "default"),
        field(&realized.applied, "-"),
        field(&realized.effective, "unknown"),
    )
}
