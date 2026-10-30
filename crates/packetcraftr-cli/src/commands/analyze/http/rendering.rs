// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output::http as wire;
use crate::rendering::{comma_separated, render_optional, write_stdout_line, write_summary_line};

pub(super) fn render_message(
    invocation: &crate::invocation::Invocation,
    message: &wire::Message,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
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
    write_stdout_line(
        invocation,
        format_args!(
            "HTTP tcp:{} message={} status={} {} body_bytes={} request={} frames={}",
            message.stream,
            message.index,
            message.status,
            start,
            message.body_bytes,
            render_optional(message.request, |value| value.to_string()),
            if frames.is_empty() { "none" } else { &frames },
        ),
    )?;
    if presentation.verbose {
        for header in &message.headers {
            write_stdout_line(
                invocation,
                format_args!("  {}: {}", escaped(&header.name), escaped(&header.value)),
            )?;
        }
    }
    if presentation.verbose {
        for trailer in &message.trailers {
            write_stdout_line(
                invocation,
                format_args!(
                    "  trailer {}: {}",
                    escaped(&trailer.name),
                    escaped(&trailer.value)
                ),
            )?;
        }
        write_stdout_line(
            invocation,
            format_args!("  header bytes: {}", message.header_wire_hex),
        )?;
        presentation.details(invocation, "Provenance", &message.sources)?;
    }
    if let Some(error) = &message.error {
        write_stdout_line(invocation, format_args!("  error: {error}"))?;
    }
    Ok(())
}

pub(super) fn render_issue(
    invocation: &crate::invocation::Invocation,
    issue: &wire::Issue,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "  TCP stream={} frame={} status={}",
            issue.stream, issue.number, issue.status,
        ),
    )
}

pub(super) fn render_complete(
    invocation: &crate::invocation::Invocation,
    complete: &wire::Complete,
) -> Result<(), CliError> {
    write_summary_line(
        invocation,
        format_args!(
            "{} HTTP/1 messages, {} complete, {} incomplete, {} malformed; {} requests without a captured final response",
            complete.summary.messages,
            complete.summary.complete_messages,
            complete.summary.incomplete_messages,
            complete.summary.malformed_messages,
            complete.summary.requests_without_final_response
        ),
    )
}

/// Escaped so captured header bytes can neither drive the terminal nor forge another line.
fn escaped(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
