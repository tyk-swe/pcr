// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output::http2 as wire;
use crate::rendering::{comma_separated, optional_display, write_stdout_line, write_summary_line};

pub(super) fn render_frame(frame: &wire::Frame) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "H2 tcp:{} frame={} type={:#04x} stream={} length={} flags={:#04x}",
        frame.stream,
        frame.index,
        frame.frame_type,
        frame.http2_stream_id,
        frame.length,
        frame.flags,
    ))
}

pub(super) fn render_message(message: &wire::Message) -> Result<(), CliError> {
    let frames = comma_separated(message.sources.iter().map(|source| source.number));
    write_stdout_line(format_args!(
        "HTTP2 tcp:{} stream={} message={} kind={} status={} body_bytes={} request={} frames={}",
        message.stream,
        message.http2_stream_id,
        message.index,
        message.kind,
        message.status,
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
    for trailer in &message.trailers {
        write_stdout_line(format_args!(
            "  trailer {}: {}",
            escaped(&trailer.name),
            escaped(&trailer.value)
        ))?;
    }
    Ok(())
}

pub(super) fn render_issue(issue: &wire::Issue) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "  HTTP2 tcp:{} stream={} issue={} frame={} scope={} certainty={} status={} {}",
        issue.stream,
        optional_display(issue.http2_stream_id),
        escaped(&issue.code),
        issue.number,
        issue.scope,
        issue.certainty,
        issue.status,
        escaped(&issue.detail),
    ))
}

pub(super) fn render_connection(connection: &wire::Connection) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "HTTP2 tcp:{} connection startup={} status={} streams={} frames={} issues={}",
        connection.stream,
        connection.startup,
        connection.status,
        connection.streams,
        connection.frames,
        connection.issues,
    ))
}

pub(super) fn render_complete(complete: &wire::Complete) -> Result<(), CliError> {
    write_summary_line(format_args!(
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
    ))
}

fn escaped(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
