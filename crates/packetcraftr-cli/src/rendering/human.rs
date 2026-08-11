// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};

use packetcraftr::{core, output};

use super::super::errors::CliError;
use super::style::{
    error_style, style_document, style_human_line, terminal_document, terminal_safe,
};

pub(crate) fn render_diagnostics_text(
    diagnostics: &[core::diagnostic::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

pub(crate) fn render_output_diagnostics_text(
    diagnostics: &[output::envelope::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

pub(crate) fn write_stdout_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    let rendered = style_human_line(&terminal_safe(&arguments.to_string()));
    write_human_stdout(&rendered, true)
}

pub(crate) fn write_plain_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    write_machine_line(&terminal_safe(&arguments.to_string()))
}

pub(crate) fn write_machine_line(rendered: &str) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    write_terminated(&mut stdout, rendered, true)
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

pub(crate) fn emit_stdout_document(message: &str) -> Result<(), CliError> {
    let rendered = style_document(&terminal_document(message));
    write_human_stdout(&rendered, false)
}

pub(crate) fn emit_stderr_document(message: &str) -> Result<(), CliError> {
    let rendered = style_document(&terminal_document(message));
    write_human_stderr(&rendered, false)
}

pub(crate) fn emit_stderr_error(message: &str) -> Result<(), CliError> {
    let style = error_style();
    let rendered = format!("{style}error:{style:#} {}", terminal_safe(message));
    write_human_stderr(&rendered, true)
}

pub(crate) fn emit_stderr_message(message: &str) -> Result<(), CliError> {
    let rendered = style_human_line(&terminal_safe(message));
    write_human_stderr(&rendered, true)
}

fn write_human_stdout(rendered: &str, append_newline: bool) -> Result<(), CliError> {
    let stdout = anstream::stdout();
    let mut stdout = stdout.lock();
    write_terminated(&mut stdout, rendered, append_newline)
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

fn write_human_stderr(rendered: &str, append_newline: bool) -> Result<(), CliError> {
    let stderr = anstream::stderr();
    let mut stderr = stderr.lock();
    write_terminated(&mut stderr, rendered, append_newline)
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

fn write_terminated(
    writer: &mut impl Write,
    rendered: &str,
    append_newline: bool,
) -> io::Result<()> {
    writer.write_all(rendered.as_bytes())?;
    if append_newline || !rendered.ends_with('\n') {
        writer.write_all(b"\n")?;
    }
    writer.flush()
}
