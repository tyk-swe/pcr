// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
#[cfg(test)]
use std::{cell::RefCell, str};

use packetcraftr::{output, packet};

use super::super::errors::CliError;
use super::style::{
    error_style, style_document, style_human_line, terminal_document, terminal_safe,
};

pub(crate) fn render_diagnostics_text(
    diagnostics: &[packet::diagnostic::Diagnostic],
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
    #[cfg(test)]
    if let Some(result) = write_test_stdout(rendered, true) {
        return result.map_err(|source| CliError::new(5, format!("write stdout failed: {source}")));
    }
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
    #[cfg(test)]
    if let Some(result) = write_test_stdout(rendered, append_newline) {
        return result.map_err(|source| CliError::new(5, format!("write stdout failed: {source}")));
    }
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

#[cfg(test)]
thread_local! {
    static TEST_STDOUT: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn write_test_stdout(rendered: &str, append_newline: bool) -> Option<io::Result<()>> {
    TEST_STDOUT.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|writer| write_terminated(writer, rendered, append_newline))
    })
}

#[cfg(test)]
pub(crate) fn capture_stdout<T>(operation: impl FnOnce() -> T) -> (T, String) {
    TEST_STDOUT.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "test stdout capture cannot be nested"
        );
        *slot.borrow_mut() = Some(Vec::new());
        let result = operation();
        let bytes = slot
            .borrow_mut()
            .take()
            .expect("test stdout capture remains installed");
        let rendered = str::from_utf8(&bytes)
            .expect("CLI output is valid UTF-8")
            .to_owned();
        (result, rendered)
    })
}
