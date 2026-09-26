// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Machine, capture-file, and human-terminal rendering.

mod capture_file;
mod capture_writer;
mod dns;
mod frame;
mod human;
mod machine;
mod ndjson;
mod style;

pub(crate) use capture_file::{stream_capture_error, write_capture_file, write_raw};
pub(crate) use capture_writer::{LinkCaptureWriter, SourceCaptureWriter, finish_compressed_output};

pub(crate) use dns::{render_dns_fields, render_dns_record, render_dns_records};
pub(crate) use frame::{captured_frame_text, render_frame_text, render_undecoded};

pub(crate) use human::{
    HumanWriteError, comma_separated, document_spelling, emit_stderr_document, emit_stderr_error,
    emit_stderr_message, emit_stdout_document, optional_debug, optional_display,
    render_diagnostics_stderr, render_diagnostics_text, spaced_hex, write_hex_line,
    write_stdout_line, write_stdout_line_with_interrupt, write_summary_line,
};

pub(crate) use machine::{
    bounded_json_len, bounded_pretty_json_len, emit_aggregate, emit_aggregate_with_stats,
    emit_json, emit_published,
};

pub(crate) use ndjson::{
    OUTPUT_TIMEOUT_MS, StreamEncoder, stdout_stream, write_unattributed_error,
};

pub(crate) use style::terminal_document;
