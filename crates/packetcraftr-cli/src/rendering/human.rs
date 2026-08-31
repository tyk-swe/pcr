// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

use std::fmt::{self, Write as _};
use std::io::{self, Write};

use packetcraftr::{core, output};

use super::style::{
    error_style, style_document, style_human_line, style_summary_line, terminal_document,
    terminal_safe,
};
use crate::errors::CliError;

/// The diagnostic fields the human renderer prints.
///
/// The core and envelope diagnostics carry the same three fields under
/// different types, and both render identically.
pub(crate) trait DiagnosticLine {
    fn severity(&self) -> core::diagnostic::Severity;
    fn code(&self) -> &str;
    fn message(&self) -> &str;
}

impl DiagnosticLine for core::diagnostic::Diagnostic {
    fn severity(&self) -> core::diagnostic::Severity {
        self.severity
    }

    fn code(&self) -> &str {
        &self.code
    }

    fn message(&self) -> &str {
        &self.message
    }
}

impl DiagnosticLine for output::envelope::Diagnostic {
    fn severity(&self) -> core::diagnostic::Severity {
        self.severity
    }

    fn code(&self) -> &str {
        &self.code
    }

    fn message(&self) -> &str {
        &self.message
    }
}

/// One diagnostic line, severity spelled exactly as the JSON document spells
/// it. Written once so the stdout and stderr renderers cannot drift apart.
fn diagnostic_line(diagnostic: &impl DiagnosticLine) -> String {
    format!(
        "{} {}: {}",
        diagnostic.severity().as_str(),
        diagnostic.code(),
        diagnostic.message()
    )
}

pub(crate) fn render_diagnostics_text(diagnostics: &[impl DiagnosticLine]) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!("{}", diagnostic_line(diagnostic)))?;
    }
    Ok(())
}

/// The same lines on stderr, for a command whose stdout carries capture bytes
/// or NDJSON records a diagnostic must not be interleaved with.
pub(crate) fn render_diagnostics_stderr(
    diagnostics: &[impl DiagnosticLine],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        emit_stderr_message(&diagnostic_line(diagnostic))?;
    }
    Ok(())
}

pub(crate) fn render_optional<T>(value: Option<T>, render: impl FnOnce(T) -> String) -> String {
    value.map_or_else(|| "none".to_owned(), render)
}

pub(crate) fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    render_optional(value, |value| value.to_string())
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

pub(crate) fn captured_frame_text(frame: &output::frame::Captured) -> impl fmt::Display + '_ {
    CapturedFrameText(frame)
}

struct CapturedFrameText<'a>(&'a output::frame::Captured);

impl fmt::Display for CapturedFrameText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let frame = self.0;
        write!(
            formatter,
            "dlt={} caplen={} wirelen={} {}",
            frame.link_type,
            frame.captured_length,
            frame.original_length,
            spaced_hex(frame.bytes())
        )
    }
}

pub(crate) fn write_stdout_line(arguments: fmt::Arguments<'_>) -> Result<(), CliError> {
    let rendered = style_human_line(&terminal_safe(&arguments.to_string()));
    write_human_stdout(&rendered, true)
}

/// The one line a text renderer ends with, naming what the command completed.
///
/// Success colour is a property of this call, not of the words the line
/// happens to start with.
pub(crate) fn write_summary_line(arguments: fmt::Arguments<'_>) -> Result<(), CliError> {
    let rendered = style_summary_line(&terminal_safe(&arguments.to_string()));
    write_human_stdout(&rendered, true)
}

pub(crate) fn write_plain_line(arguments: fmt::Arguments<'_>) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_fmt(arguments)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(Kind::Io, format!("write stdout failed: {source}")))
}

pub(crate) fn emit_stdout_document(message: &str) -> Result<(), CliError> {
    let rendered = style_document(&terminal_document(message));
    write_human_stdout(&rendered, false)
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

fn write_human_stdout(rendered: &str, append_newline: bool) -> Result<(), CliError> {
    let stdout = anstream::stdout();
    let mut stdout = stdout.lock();
    write_terminated(&mut stdout, rendered, append_newline)
        .map_err(|source| CliError::new(Kind::Io, format!("write stdout failed: {source}")))
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use packetcraftr::core::error::{Classification, Kind};

    use super::*;

    fn plain(error: &CliError) -> String {
        anstream::adapter::strip_str(&render_human_error(error)).to_string()
    }

    /// Text and JSON name a severity one way. The CLI prints `as_str`, the
    /// document serializes the same enum, and this pins them to each other.
    #[test]
    fn diagnostic_lines_spell_severity_exactly_as_the_document_does() {
        for diagnostic in [
            core::diagnostic::Diagnostic::info("decode.note", "a note"),
            core::diagnostic::Diagnostic::warning("tcp.retransmission", "duplicate segment"),
            core::diagnostic::Diagnostic::error("ipv4.checksum", "bad checksum"),
        ] {
            let severity = diagnostic.severity.as_str();
            assert_eq!(
                diagnostic_line(&diagnostic),
                format!("{severity} {}: {}", diagnostic.code, diagnostic.message),
            );
            let document = serde_json::to_value(&diagnostic).expect("diagnostics serialize");
            assert_eq!(
                document.get("severity"),
                Some(&serde_json::Value::from(severity)),
            );
        }
    }

    #[test]
    fn spaced_hex_is_lowercase_and_exact() {
        for (bytes, expected) in [
            (&[][..], ""),
            (&[0][..], "00"),
            (&[0, 10, 171, 255][..], "00 0a ab ff"),
        ] {
            assert_eq!(spaced_hex(bytes).to_string(), expected);
        }
    }

    #[test]
    fn classified_errors_render_causes_and_remediation_in_order() {
        let error = CliError::from_classification(
            Classification::new("cli.fixture", Kind::Cli, Some("try again")),
            "primary failure",
            vec!["first cause".to_owned(), "second cause".to_owned()],
        );

        assert_eq!(
            plain(&error),
            concat!(
                "error[cli.fixture]: primary failure\n",
                "caused by: first cause\n",
                "caused by: second cause\n",
                "help: try again",
            ),
        );
    }

    #[test]
    fn classified_errors_without_causes_or_remediation_have_no_empty_sections() {
        let error = CliError::from_classification(
            Classification::new("io.fixture", Kind::Io, None),
            "primary failure",
            Vec::new(),
        );

        assert_eq!(plain(&error), "error[io.fixture]: primary failure");
    }

    #[test]
    fn empty_causes_and_remediation_do_not_create_empty_sections() {
        let error = CliError::from_classification(
            Classification::new("cli.fixture", Kind::Cli, Some("  ")),
            "primary failure",
            vec![String::new(), "\t".to_owned()],
        );

        assert_eq!(plain(&error), "error[cli.fixture]: primary failure");
    }

    #[test]
    fn fallback_classifications_for_every_kind_are_rendered() {
        for (kind, code) in [
            (Kind::Cli, "cli.error"),
            (Kind::Packet, "packet.error"),
            (Kind::Capability, "capability.unavailable"),
            (Kind::Io, "io.runtime"),
            (Kind::Policy, "policy.denied"),
            (Kind::Internal, "internal.error"),
        ] {
            let error = CliError::new(kind, "fallback failure");
            assert_eq!(plain(&error), format!("error[{code}]: fallback failure"));
        }
    }

    #[test]
    fn terminal_safety_applies_to_every_rendered_error_field() {
        let error = CliError::from_classification(
            Classification::new(
                "cli.\u{202e}code\x1b",
                Kind::Cli,
                Some("help:\t\u{2066}now\r\n"),
            ),
            "primary\n\t\u{200f}\x1bmessage",
            vec!["cause\r\n\u{200b}one".to_owned(), "cause two".to_owned()],
        );

        assert_eq!(
            plain(&error),
            concat!(
                "error[cli.\\u{202e}code\\u{1b}]: ",
                "primary\\n\\t\\u{200f}\\u{1b}message\n",
                "caused by: cause\\r\\n\\u{200b}one\n",
                "caused by: cause two\n",
                "help: help:\\t\\u{2066}now\\r\\n",
            ),
        );
    }

    #[test]
    fn identical_primary_causes_are_not_rendered_twice() {
        let error = CliError::from_classification(
            Classification::new("cli.fixture", Kind::Cli, None),
            "same message",
            vec![
                "same message".to_owned(),
                "retained cause".to_owned(),
                "same message".to_owned(),
            ],
        );

        assert_eq!(
            plain(&error),
            "error[cli.fixture]: same message\ncaused by: retained cause",
        );
    }

    #[test]
    fn disabled_or_noninteractive_streams_strip_renderer_styles() {
        let error = CliError::from_classification(
            Classification::new("cli.fixture", Kind::Cli, Some("try again")),
            "primary failure",
            vec!["cause".to_owned()],
        );
        let rendered = render_human_error(&error);
        let expected = plain(&error).into_bytes();

        for choice in [anstream::ColorChoice::Never, anstream::ColorChoice::Auto] {
            let mut stream = anstream::AutoStream::new(Vec::new(), choice);
            stream
                .write_all(rendered.as_bytes())
                .expect("adaptive stream must write");
            let output = stream.into_inner();
            assert!(!output.windows(2).any(|window| window == b"\x1b["));
            assert_eq!(output, expected);
        }
    }
}
