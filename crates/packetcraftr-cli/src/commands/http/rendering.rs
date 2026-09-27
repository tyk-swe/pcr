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

/// One settled header-association row: its emission index, outcome,
/// connection identity, the message indices it links, and the signed
/// capture-observed intervals between its markers (`none` when absent).
pub(super) fn render_transaction(transaction: &wire::Transaction) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "  transaction={} outcome={} stream={} generation={} request={} response={} status={} wait={} span={}",
        transaction.index,
        transaction.outcome,
        transaction.stream,
        transaction.generation,
        optional_display(transaction.request),
        optional_display(transaction.response),
        optional_display(transaction.response_status),
        interval(transaction.response_header_wait),
        interval(transaction.response_header_span),
    ))
}

/// The published artifact's one sanitized line — index, byte count, digest,
/// and destination — printed between the message rows and the summary. Body
/// bytes themselves never appear in output.
pub(super) fn render_body_export(complete: &wire::Complete) -> Result<(), CliError> {
    if let Some(export) = &complete.body_export {
        write_stdout_line(format_args!(
            "body message={} bytes={} sha256={} path={}",
            export.message, export.bytes, export.sha256, export.path,
        ))?;
    }
    Ok(())
}

pub(super) fn render_complete(complete: &wire::Complete) -> Result<(), CliError> {
    write_summary_line(format_args!(
        "{} HTTP/1 messages, {} complete, {} incomplete, {} malformed; {} requests without a captured final response",
        complete.summary.messages,
        complete.summary.complete_messages,
        complete.summary.incomplete_messages,
        complete.summary.malformed_messages,
        complete.summary.requests_without_final_response
    ))?;
    if let Some(summary) = &complete.transaction_summary {
        write_summary_line(format_args!(
            "{} header transactions: {} paired, {} unanswered, {} orphan responses; {} negative waits, {} negative spans",
            summary.transactions,
            summary.paired,
            summary.unanswered,
            summary.orphan_responses,
            summary.negative_header_waits,
            summary.negative_header_spans,
        ))?;
    }
    Ok(())
}

/// A signed capture-observed interval in nanoseconds; negative intervals
/// stay visible, as the JSON document keeps them.
fn interval(interval: Option<wire::Interval>) -> String {
    interval.map_or_else(
        || "none".to_owned(),
        |interval| {
            let sign = if interval.negative { "-" } else { "" };
            format!("{sign}{}ns", interval.nanoseconds)
        },
    )
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
