// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `http`'s text output. Captured start lines and header fields are
//! escaped, then written through the sanitizing writer, and every status
//! prints in its JSON spelling.

use crate::errors::CliError;
use crate::output::http as wire;
use crate::rendering::{comma_separated, optional_display, write_stdout_line, write_summary_line};

/// One message line, then its header fields and any parse error.
pub(super) fn render_message(message: &wire::Message) -> Result<(), CliError> {
    let start = match &message.start {
        Some(wire::StartLine::Request { method, target, .. }) => {
            format!("{} {}", escaped(method), escaped(target))
        }
        Some(wire::StartLine::Response { status, reason, .. }) => {
            format!("{status} {}", escaped(reason))
        }
        None => "partial headers".to_owned(),
    };
    let frames = comma_separated(message.sources.iter().map(|source| source.number));
    write_stdout_line(format_args!(
        "HTTP tcp:{} message={} status={} {} body_bytes={} request={} frames={}",
        message.stream,
        message.index,
        message.status,
        start,
        message.body_bytes,
        optional_display(message.request),
        if frames.is_empty() { "none" } else { &frames },
    ))?;
    for header in &message.headers {
        write_stdout_line(format_args!(
            "  {}: {}",
            escaped(&header.name),
            escaped(&header.value)
        ))?;
    }
    if let Some(error) = &message.error {
        write_stdout_line(format_args!("  error: {error}"))?;
    }
    Ok(())
}

pub(super) fn render_issue(issue: &wire::Issue) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "  TCP stream={} frame={} status={}",
        issue.stream, issue.number, issue.status,
    ))
}

pub(super) fn render_complete(complete: &wire::Complete) -> Result<(), CliError> {
    write_summary_line(format_args!(
        "{} HTTP/1 messages, {} complete, {} incomplete, {} malformed; {} requests without a captured final response",
        complete.summary.messages,
        complete.summary.complete_messages,
        complete.summary.incomplete_messages,
        complete.summary.malformed_messages,
        complete.summary.requests_without_final_response
    ))
}

/// Captured text with every control character, quote, and non-ASCII
/// character spelled as a Rust escape, so header bytes can neither drive the
/// terminal nor forge another line.
fn escaped(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

#[cfg(test)]
mod tests {
    use super::escaped;

    #[test]
    fn escaping_leaves_no_control_or_bidirectional_characters() {
        let rendered = escaped("X-\u{1b}[31mEvil\r\nSet-Cookie:\u{202e} a");
        assert!(!rendered.chars().any(char::is_control), "{rendered}");
        assert!(!rendered.contains('\u{202e}'), "{rendered}");
        assert_eq!(rendered, "X-\\u{1b}[31mEvil\\r\\nSet-Cookie:\\u{202e} a");
    }
}
