// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;

use packetcraftr_core::error::{Coordinate, Kind};

use super::sanitize::{terminal_document, terminal_safe};
use super::stdout::write_terminated;
use super::style::{severity_style, style_document, style_warning_line};
use crate::errors::CliError;
use crate::output::envelope::Severity;

pub(crate) fn emit_stderr_document(message: &str) -> Result<(), CliError> {
    write_stderr(&style_document(&terminal_document(message)))
}

pub(crate) fn emit_stderr_error(error: &CliError) -> Result<(), CliError> {
    write_stderr(&render_human_error(error))
}

/// A failed structured report falls back to stderr once, retaining both failures.
pub(crate) fn report_structured_error(
    error: CliError,
    exit_code: u8,
    emit: impl FnOnce(&CliError) -> Result<(), CliError>,
    stderr: impl FnOnce(&CliError) -> Result<(), CliError>,
) -> std::process::ExitCode {
    match emit(&error) {
        Ok(()) => std::process::ExitCode::from(exit_code),
        Err(write_error) => {
            let code = write_error.exit_code();
            let _ = stderr(&error.with_secondary("error reporting", write_error));
            std::process::ExitCode::from(code)
        }
    }
}

fn render_human_error(error: &CliError) -> String {
    let style = severity_style(Severity::Error);
    let code = terminal_safe(error.classification.code.as_str());
    let message = terminal_safe(&error.message);
    let mut rendered = format!("{style}error{style:#}[{code}]: {message}");

    let context = match error.context() {
        Some(Coordinate::SourceFrame(frame)) => Some(format!("source frame {frame}")),
        Some(Coordinate::ProbeSequence(sequence)) => Some(format!("probe sequence {sequence}")),
        Some(Coordinate::Attempt(attempt)) => Some(format!("attempt {attempt}")),
        Some(Coordinate::CaseIndex(index)) => Some(format!("case index {index}")),
        _ => None,
    };
    if let Some(context) = context {
        let _ = write!(rendered, "\n{style}at:{style:#} {context}");
    }

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
    write_stderr(&terminal_safe(message))
}

pub(crate) fn emit_stderr_warning(message: &str) -> Result<(), CliError> {
    write_stderr(&style_warning_line(&terminal_safe(message)))
}

pub(super) fn write_stderr(rendered: &str) -> Result<(), CliError> {
    let stderr = anstream::stderr();
    let mut stderr = stderr.lock();
    write_terminated(&mut stderr, rendered)
        .map_err(|source| CliError::wrapping(Kind::Io, "write stderr failed", &source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::error::Classification;
    use std::io;
    use std::process::ExitCode;

    #[test]
    fn text_errors_sanitize_details_with_locations() {
        for (context, expected) in [
            (Coordinate::SourceFrame(7), "source frame 7"),
            (Coordinate::ProbeSequence(8), "probe sequence 8"),
            (Coordinate::Attempt(2), "attempt 2"),
            (Coordinate::CaseIndex(0), "case index 0"),
        ] {
            let error = CliError::from_classification(
                Classification::new(
                    packetcraftr_core::error::Code::PacketTest,
                    Kind::Packet,
                    Some("repair\tinput"),
                ),
                "bad\ninput\u{1b}",
                vec!["cause\r\u{202e}".into()],
            )
            .with_context(Some(context));
            let rendered = terminal_document(&render_human_error(&error));
            assert!(rendered.contains(expected));
            assert!(rendered.contains("bad\\ninput\\u{1b}"));
            assert!(rendered.contains("cause\\r\\u{202e}"));
            assert!(rendered.contains("repair\\tinput"));
        }
    }

    #[test]
    fn reporting_fallback_preserves_original_failure() {
        let error = CliError::new(Kind::Usage, "invalid argument");
        let code = report_structured_error(
            error,
            2,
            |_| {
                Err(CliError::wrapping(
                    Kind::Io,
                    "write stdout failed",
                    &io::Error::other("closed pipe"),
                ))
            },
            |combined| {
                assert!(combined.message.contains("invalid argument"));
                assert!(combined.message.contains("write stdout failed"));
                assert!(combined.causes.iter().any(|cause| cause == "closed pipe"));
                Err(CliError::new(Kind::Io, "stderr is also closed"))
            },
        );
        assert_eq!(code, ExitCode::from(5));
    }

    #[test]
    fn successful_reporting_preserves_exit_status() {
        for code in [2, 3, 4, 5, 6, 70, 130] {
            assert_eq!(
                report_structured_error(
                    CliError::new(Kind::Usage, "original failure"),
                    code,
                    |_| Ok(()),
                    |_| panic!("successful reporting must not fall back to stderr"),
                ),
                ExitCode::from(code)
            );
        }
    }
}
