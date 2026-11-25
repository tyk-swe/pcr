// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::output as wire;
use crate::errors::CliError;
use crate::terminal::{
    comma_separated, escaped, render_optional, write_stdout_line, write_summary_line,
};

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
        crate::commands::offline_analysis::render_headers_and_trailers(
            invocation,
            message
                .headers
                .iter()
                .map(|header| (header.name.as_str(), header.value.as_str())),
            message
                .trailers
                .iter()
                .map(|trailer| (trailer.name.as_str(), trailer.value.as_str())),
        )?;
        write_stdout_line(
            invocation,
            format_args!("  header bytes: {}", message.header_wire_hex),
        )?;
        crate::terminal::write_details(invocation, presentation, "Provenance", &message.sources)?;
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
    crate::commands::offline_analysis::render_tcp_stream_issue(invocation, issue)
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
