// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod diagnostics;
mod sanitize;
mod stderr;
mod stdout;
mod style;
mod table;
mod text;

pub(crate) use diagnostics::{
    render_diagnostics_stderr, render_diagnostics_text, write_coded_warning,
};
pub(crate) use sanitize::{escaped, terminal_document, terminal_safe};
pub(crate) use stderr::{
    emit_stderr_document, emit_stderr_error, emit_stderr_message, emit_stderr_warning,
    report_structured_error,
};
pub(crate) use stdout::{
    WriteError, batched, emit_stdout_document, push_stdout_line, try_write_stdout_line,
    write_details, write_stdout_block, write_stdout_line, write_summary_line, write_warning,
};
pub(crate) use table::table_row;
pub(crate) use text::{comma_separated, duration_text, render_optional};
