// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::sanitize::terminal_safe;
use super::stderr::write_stderr;
use super::stdout::write_rendered;
use super::style::style_severity_line;
use crate::errors::CliError;
use crate::invocation::Invocation;
use crate::output::envelope::{Diagnostic, Severity};

fn coded_line(severity: Severity, code: &str, message: &str) -> String {
    style_severity_line(severity, &terminal_safe(&format!(" {code}: {message}")))
}

fn diagnostic_line(diagnostic: impl Into<Diagnostic>) -> String {
    let diagnostic = diagnostic.into();
    coded_line(diagnostic.severity, diagnostic.code, &diagnostic.message)
}

pub(crate) fn render_diagnostics_text<D: Clone + Into<Diagnostic>>(
    invocation: &Invocation,
    diagnostics: &[D],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_rendered(invocation, &diagnostic_line(diagnostic.clone()))?;
    }
    Ok(())
}

pub(crate) fn render_diagnostics_stderr<D: Clone + Into<Diagnostic>>(
    diagnostics: &[D],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stderr(&diagnostic_line(diagnostic.clone()))?;
    }
    Ok(())
}

pub(crate) fn write_coded_warning(
    invocation: &Invocation,
    code: &str,
    message: &str,
) -> Result<(), CliError> {
    Ok(write_rendered(
        invocation,
        &coded_line(Severity::Warning, code, message),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_is_coloured_from_the_diagnostic_and_text_is_sanitized() {
        let line = coded_line(
            Severity::Error,
            "packet.bad",
            "broken\u{1b}[31m\nerror forged",
        );
        let plain = anstream::adapter::strip_str(&line).to_string();
        assert_eq!(plain, "error packet.bad: broken\\u{1b}[31m\\nerror forged");
        assert_eq!(
            line.strip_suffix(&plain["error".len()..]),
            Some(style_severity_line(Severity::Error, "").as_str())
        );
        assert_ne!(
            style_severity_line(Severity::Error, ""),
            style_severity_line(Severity::Warning, "")
        );
    }
}
