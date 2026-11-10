// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::io::{self, Write};

use packetcraftr_core::budget::Interrupted;
use packetcraftr_core::error::Kind;

use super::sanitize::{terminal_document, terminal_safe};
use super::style::{style_document, style_summary_line, style_warning_line};
use crate::errors::CliError;
use crate::invocation::{Invocation, Presentation};
use crate::output::stream::BATCH_BYTES;

pub(crate) enum WriteError {
    Interrupted(Interrupted),
    Write(io::Error),
}

impl From<WriteError> for CliError {
    fn from(error: WriteError) -> Self {
        match error {
            WriteError::Interrupted(interrupted) => Self::classified(interrupted),
            WriteError::Write(source) => Self::stdout("write stdout failed", &source),
        }
    }
}

pub(crate) fn write_stdout_line(
    invocation: &Invocation,
    arguments: fmt::Arguments<'_>,
) -> Result<(), CliError> {
    Ok(try_write_stdout_line(invocation, arguments)?)
}

pub(crate) fn try_write_stdout_line(
    invocation: &Invocation,
    arguments: fmt::Arguments<'_>,
) -> Result<(), WriteError> {
    write_rendered(invocation, &terminal_safe(&arguments.to_string()))
}

pub(crate) fn push_stdout_line(block: &mut String, line: &str) {
    block.push_str(&terminal_safe(line));
    block.push('\n');
}

/// Writes lines from [`push_stdout_line`] with one interruption check and flush.
pub(crate) fn write_stdout_block(invocation: &Invocation, block: &str) -> Result<(), CliError> {
    if block.is_empty() {
        return Ok(());
    }
    Ok(write_rendered(invocation, block)?)
}

pub(crate) fn write_warning(
    invocation: &Invocation,
    arguments: fmt::Arguments<'_>,
) -> Result<(), CliError> {
    Ok(write_rendered(
        invocation,
        &style_warning_line(&terminal_safe(&arguments.to_string())),
    )?)
}

pub(crate) fn write_summary_line(
    invocation: &Invocation,
    arguments: fmt::Arguments<'_>,
) -> Result<(), CliError> {
    Ok(write_rendered(
        invocation,
        &style_summary_line(&terminal_safe(&arguments.to_string())),
    )?)
}

pub(crate) fn emit_stdout_document(invocation: &Invocation, message: &str) -> Result<(), CliError> {
    Ok(write_rendered(
        invocation,
        &style_document(&terminal_document(message)),
    )?)
}

pub(crate) fn write_details(
    invocation: &Invocation,
    presentation: Presentation,
    label: &str,
    value: &impl serde::Serialize,
) -> Result<(), CliError> {
    if !presentation.verbose {
        return Ok(());
    }
    let text = serde_json::to_string_pretty(value).map_err(|error| {
        CliError::new(Kind::Internal, format!("cannot render {label}: {error}"))
    })?;
    write_stdout_line(invocation, format_args!("{label}:"))?;
    emit_stdout_document(invocation, &text)
}

/// Holds the human lines `run` writes and sends them to stdout a batch at a
/// time, flushing what is left even when `run` fails.
pub(crate) fn batched<T>(
    invocation: &Invocation,
    run: impl FnOnce() -> Result<T, CliError>,
) -> Result<T, CliError> {
    invocation.batch_stdout();
    let result = run();
    let flushed = match invocation.stdout_batch().take() {
        Some(mut pending) => write_batch(&mut pending, styled_stdout()),
        None => Ok(()),
    };
    let value = result?;
    flushed.map_err(|source| CliError::stdout("write stdout failed", &source))?;
    Ok(value)
}

pub(super) fn write_rendered(invocation: &Invocation, rendered: &str) -> Result<(), WriteError> {
    invocation
        .check_interrupted()
        .map_err(WriteError::Interrupted)?;
    let mut batch = invocation.stdout_batch();
    let written = match batch.as_mut() {
        None => write_terminated(&mut styled_stdout(), rendered),
        Some(pending) => hold_line(pending, rendered, styled_stdout),
    };
    written.map_err(WriteError::Write)
}

fn hold_line<W: Write>(
    pending: &mut Vec<u8>,
    rendered: &str,
    stdout: impl FnOnce() -> W,
) -> io::Result<()> {
    write_terminated(pending, rendered)?;
    if pending.len() < BATCH_BYTES {
        return Ok(());
    }
    write_batch(pending, stdout())
}

fn write_batch(pending: &mut Vec<u8>, mut stdout: impl Write) -> io::Result<()> {
    let written = stdout.write_all(pending).and_then(|()| stdout.flush());
    pending.clear();
    written
}

fn styled_stdout() -> anstream::AutoStream<io::StdoutLock<'static>> {
    static CHOICE: std::sync::LazyLock<anstream::ColorChoice> =
        std::sync::LazyLock::new(|| anstream::stdout().current_choice());
    anstream::AutoStream::new(io::stdout(), *CHOICE).lock()
}

pub(super) fn write_terminated(writer: &mut impl Write, rendered: &str) -> io::Result<()> {
    writer.write_all(rendered.as_bytes())?;
    if !rendered.ends_with('\n') {
        writer.write_all(b"\n")?;
    }
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_lines_reach_stdout_in_order_once_a_batch_fills() {
        let line = "x".repeat(99);
        let lines = BATCH_BYTES / 100;
        let mut pending = Vec::new();
        let mut written = Vec::new();
        for _ in 0..lines - 1 {
            hold_line(&mut pending, &line, || &mut written).unwrap();
        }
        assert!(written.is_empty());
        for _ in 0..lines {
            hold_line(&mut pending, &line, || &mut written).unwrap();
        }
        assert!(written.len() >= BATCH_BYTES);
        assert!(pending.len() < BATCH_BYTES);
        written.extend_from_slice(&pending);
        assert_eq!(
            written,
            format!("{line}\n").repeat(2 * lines - 1).into_bytes()
        );

        let mut pending = Vec::new();
        let mut written = Vec::new();
        let exactly_full = "x".repeat(BATCH_BYTES - 1);
        hold_line(&mut pending, &exactly_full, || &mut written).unwrap();
        assert_eq!(written.len(), BATCH_BYTES);
        assert!(pending.is_empty());
    }
}
