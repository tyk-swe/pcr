// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output::http2 as wire;
use crate::rendering::{comma_separated, render_optional, write_stdout_line, write_summary_line};

pub(super) fn render_frame(
    invocation: &crate::invocation::Invocation,
    frame: &wire::Frame,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "H2 tcp:{} frame={} type={:#04x} stream={} length={} flags={:#04x}",
            frame.stream,
            frame.index,
            frame.frame_type,
            frame.http2_stream_id,
            frame.length,
            frame.flags,
        ),
    )
}

pub(super) fn render_message(
    invocation: &crate::invocation::Invocation,
    message: &wire::Message,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    let frames = comma_separated(message.sources.iter().map(|source| source.number));
    write_stdout_line(
        invocation,
        format_args!(
            "HTTP2 tcp:{} stream={} message={} kind={} status={} body_bytes={} request={} frames={}",
            message.stream,
            message.http2_stream_id,
            message.index,
            message.kind,
            message.status,
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
    }
    if presentation.verbose {
        presentation.details(invocation, "Header block bytes", &message.header_blocks_hex)?;
        presentation.details(invocation, "Provenance", &message.sources)?;
        presentation.details(
            invocation,
            "Compression dependencies",
            &message.compression_sources,
        )?;
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
            "  HTTP2 tcp:{} stream={} issue={} frame={} scope={} certainty={} status={} {}",
            issue.stream,
            render_optional(issue.http2_stream_id, |value| value.to_string()),
            escaped(&issue.code),
            issue.number,
            issue.scope,
            issue.certainty,
            issue.status,
            escaped(&issue.detail),
        ),
    )
}

pub(super) fn render_connection(
    invocation: &crate::invocation::Invocation,
    connection: &wire::Connection,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "HTTP2 tcp:{} connection startup={} status={} streams={} frames={} issues={}",
            connection.stream,
            connection.startup,
            connection.status,
            connection.streams,
            connection.frames,
            connection.issues,
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
            "{} HTTP/2 connections ({} prior knowledge, {} h2c, {} unsupported); {} messages ({} complete, {} incomplete, {} malformed, {} limited); {} issues",
            complete.summary.connections,
            complete.summary.prior_knowledge_connections,
            complete.summary.upgraded_connections,
            complete.summary.unsupported_connections,
            complete.summary.messages,
            complete.summary.complete_messages,
            complete.summary.incomplete_messages,
            complete.summary.malformed_messages,
            complete.summary.limited_messages,
            complete.summary.issues
        ),
    )
}

fn escaped(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
