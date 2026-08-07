// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! CLI rendering pipeline for machine serialization, stream sequencing, capture files, and styled human terminal output.

mod capture_file;
mod human;
mod machine;
mod sequence;
mod style;

pub(crate) use capture_file::{capture_file_format, write_capture_file, write_raw};

pub(crate) use human::{
    emit_stderr_document, emit_stderr_error, emit_stderr_message, emit_stdout_document,
    render_diagnostics_text, render_output_diagnostics_text, write_plain_line, write_stdout_line,
};

pub(crate) use machine::{emit_json, emit_json_compact, output_timestamp_text, spaced_hex};

pub(crate) use sequence::{emit_stream_record, next_stream_sequence};

pub(crate) use style::terminal_document;
