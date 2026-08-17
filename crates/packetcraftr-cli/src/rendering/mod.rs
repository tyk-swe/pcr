// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Machine, capture-file, and human-terminal rendering.

mod capture_file;
mod capture_writer;
mod human;
mod machine;
mod ndjson;
mod style;

pub(crate) use capture_file::{capture_file_format, write_capture_file, write_raw};
pub(crate) use capture_writer::CaptureWriter;

pub(crate) use human::{
    emit_stderr_document, emit_stderr_error, emit_stderr_message, emit_stdout_document,
    render_diagnostics_text, render_output_diagnostics_text, write_plain_line, write_stdout_line,
};

pub(crate) use machine::{
    captured_frame_text, comma_separated, emit_aggregate, emit_aggregate_with_stats, emit_json,
    emit_json_compact, optional_display, output_timestamp_text, render_optional, spaced_hex,
};

pub(crate) use ndjson::{emit, emit_next, emit_with_stats};

pub(crate) use style::terminal_document;
