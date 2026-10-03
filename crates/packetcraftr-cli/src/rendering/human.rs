// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::Kind;

use std::fmt::{self, Write as _};
use std::io::{self, Write};

use packetcraftr_core::budget::Interrupted;

use super::stdout::stdout_error;
use super::style::{
    error_style, style_document, style_human_line, style_summary_line, terminal_document,
    terminal_safe,
};
use crate::errors::CliError;
use crate::output;

fn diagnostic_line(diagnostic: impl Into<output::diagnostic::Diagnostic>) -> String {
    let diagnostic = diagnostic.into();
    format!(
        "{} {}: {}",
        diagnostic.severity.as_str(),
        diagnostic.code,
        diagnostic.message
    )
}

pub(crate) fn render_diagnostics_text<D: Clone + Into<output::diagnostic::Diagnostic>>(
    diagnostics: &[D],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!("{}", diagnostic_line(diagnostic.clone())))?;
    }
    Ok(())
}

pub(crate) fn render_diagnostics_stderr<D: Clone + Into<output::diagnostic::Diagnostic>>(
    diagnostics: &[D],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        emit_stderr_message(&diagnostic_line(diagnostic.clone()))?;
    }
    Ok(())
}

pub(crate) fn render_optional<T>(value: Option<T>, render: impl FnOnce(T) -> String) -> String {
    value.map_or_else(|| "none".to_owned(), render)
}

pub(crate) fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    render_optional(value, |value| value.to_string())
}

/// A duration in milliseconds to the microsecond, such as `12.345ms`.
pub(crate) fn duration_text(duration: std::time::Duration) -> String {
    format!("{:.3}ms", duration.as_secs_f64() * 1_000.0)
}

pub(crate) fn optional_duration(value: Option<std::time::Duration>) -> String {
    render_optional(value, duration_text)
}

pub(crate) fn encapsulation_text(path: &[output::analysis::EncapsulationIdentifier]) -> String {
    if path.is_empty() {
        "none".to_owned()
    } else {
        comma_separated(path)
    }
}

pub(crate) fn document_spelling(value: &impl serde::Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        Ok(other) => other.to_string(),
        Err(_) => "unknown".to_owned(),
    }
}

pub(crate) fn comma_separated<I, T>(values: I) -> String
where
    I: IntoIterator<Item = T>,
    T: ToString,
{
    values
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn spaced_hex(bytes: &[u8]) -> impl fmt::Display + '_ {
    SpacedHex(bytes)
}

struct SpacedHex<'a>(&'a [u8]);

impl fmt::Display for SpacedHex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(" ")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub(crate) fn write_stdout_line(arguments: fmt::Arguments<'_>) -> Result<(), CliError> {
    write_stdout_line_with_interrupt(arguments).map_err(HumanWriteError::into_cli_error)
}

pub(crate) enum HumanWriteError {
    Interrupted(Interrupted),
    Write(io::Error),
}

impl HumanWriteError {
    fn into_cli_error(self) -> CliError {
        match self {
            Self::Interrupted(interrupted) => crate::invocation::interruption_error(interrupted),
            Self::Write(source) => stdout_error("write stdout failed", source),
        }
    }
}

pub(crate) fn write_stdout_line_with_interrupt(
    arguments: fmt::Arguments<'_>,
) -> Result<(), HumanWriteError> {
    let rendered = style_human_line(&terminal_safe(&arguments.to_string()));
    write_human_stdout(&rendered, true)
}

pub(crate) fn write_summary_line(arguments: fmt::Arguments<'_>) -> Result<(), CliError> {
    let rendered = style_summary_line(&terminal_safe(&arguments.to_string()));
    write_human_stdout(&rendered, true).map_err(HumanWriteError::into_cli_error)
}

pub(crate) fn emit_stdout_document(message: &str) -> Result<(), CliError> {
    let rendered = style_document(&terminal_document(message));
    write_human_stdout(&rendered, false).map_err(HumanWriteError::into_cli_error)
}

pub(crate) fn emit_stderr_document(message: &str) -> Result<(), CliError> {
    let rendered = style_document(&terminal_document(message));
    write_human_stderr(&rendered, false)
}

pub(crate) fn emit_stderr_error(error: &CliError) -> Result<(), CliError> {
    let rendered = render_human_error(error);
    write_human_stderr(&rendered, true)
}

fn render_human_error(error: &CliError) -> String {
    let style = error_style();
    let code = terminal_safe(error.classification.code);
    let message = terminal_safe(&error.message);
    let mut rendered = format!("{style}error{style:#}[{code}]: {message}");

    for cause in &error.causes {
        if cause.trim().is_empty() || cause == &error.message {
            continue;
        }
        let cause = terminal_safe(cause);
        let _ = write!(rendered, "\n{style}caused by:{style:#} {cause}");
    }

    if let Some(remediation) = error.classification.remediation
        && !remediation.trim().is_empty()
    {
        let remediation = terminal_safe(remediation);
        let _ = write!(rendered, "\n{style}help:{style:#} {remediation}");
    }

    rendered
}

pub(crate) fn emit_stderr_message(message: &str) -> Result<(), CliError> {
    let rendered = style_human_line(&terminal_safe(message));
    write_human_stderr(&rendered, true)
}

fn write_human_stdout(rendered: &str, append_newline: bool) -> Result<(), HumanWriteError> {
    crate::invocation::check_interrupted().map_err(HumanWriteError::Interrupted)?;
    let stdout = anstream::stdout();
    let mut stdout = stdout.lock();
    write_terminated(&mut stdout, rendered, append_newline).map_err(HumanWriteError::Write)
}

fn write_human_stderr(rendered: &str, append_newline: bool) -> Result<(), CliError> {
    let stderr = anstream::stderr();
    let mut stderr = stderr.lock();
    write_terminated(&mut stderr, rendered, append_newline)
        .map_err(|source| CliError::new(Kind::Io, format!("write stderr failed: {source}")))
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
