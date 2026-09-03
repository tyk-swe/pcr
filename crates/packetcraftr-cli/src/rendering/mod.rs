// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Machine, capture-file, and human-terminal rendering.

mod capture_file;
mod capture_writer;
mod human;
mod machine;
mod ndjson;
mod style;

pub(crate) use capture_file::{stdout_error, stream_capture_error, write_capture_file, write_raw};
pub(crate) use capture_writer::{LinkCaptureWriter, SourceCaptureWriter};

pub(crate) use human::{
    captured_frame_text, comma_separated, emit_stderr_document, emit_stderr_error,
    emit_stderr_message, emit_stdout_document, optional_debug, optional_display,
    render_diagnostics_stderr, render_diagnostics_text, spaced_hex, write_plain_line,
    write_stdout_line, write_summary_line,
};

pub(crate) use machine::{emit_aggregate, emit_aggregate_with_stats, emit_json};

pub(crate) use ndjson::{StreamEncoder, stdout_stream, write_unattributed_error};

#[cfg(test)]
pub(crate) use ndjson::test_support as ndjson_test_support;

pub(crate) use style::terminal_document;
