// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod aggregate;
mod analysis;
mod application;
mod capture_file;
mod capture_writer;
mod dns;
mod frame;
mod human;
mod machine;
mod ndjson;
mod presentation;
mod projection;
mod retained;
pub(crate) mod security;
mod stdout;
mod style;

pub(crate) use aggregate::render_aggregate_rows;
pub(crate) use analysis::{ip_event_sink, render_clock, render_scope};
pub(crate) use application::EventOutput;
pub(crate) use capture_file::{stream_capture_error, stream_limits, write_capture_file};
pub(crate) use capture_writer::{LinkCaptureWriter, SourceCaptureWriter, finish_compressed_output};

pub(crate) use dns::{render_dns_fields, render_dns_record, render_dns_records};
pub(crate) use frame::{CapturedFrameText, FieldTree, render_frame, render_undecoded};

pub(crate) use human::{
    HumanWriteError, comma_separated, document_spelling, duration_text, emit_stderr_document,
    emit_stderr_error, emit_stderr_message, emit_stdout_document, encapsulation_text,
    push_stdout_line, render_diagnostics_stderr, render_diagnostics_text, render_optional,
    report_structured_error, write_stdout_block, write_stdout_line,
    write_stdout_line_with_interrupt, write_summary_line,
};

pub(crate) use machine::{bounded_json_len, emit_json, emit_published};

pub(crate) use ndjson::{stdout_stream, write_unattributed_error};

pub(crate) use projection::{Projector, missing_fields_error};
pub(crate) use retained::{Retained, omitted_diagnostic};
pub(crate) use stdout::{write_hex_line, write_raw};
pub(crate) use style::terminal_document;

pub(crate) use presentation::table_row;

pub(crate) use crate::output::hex::SpacedHex;
