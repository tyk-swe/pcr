// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::invocation::Invocation;
use crate::terminal::write_stdout_line;

use super::output::{Event, Issue, Side, Terminal};

pub(super) fn event(invocation: &Invocation, event: &Event) -> Result<(), CliError> {
    match event {
        Event::Connection { connection } => {
            write_stdout_line(
                invocation,
                format_args!(
                    "HTTP/3 connection={} QUIC version={:#010x} capture frames={}..{} transport_incomplete={}",
                    connection.connection,
                    connection.version,
                    connection.first_frame,
                    connection.last_frame,
                    connection.transport_incomplete
                ),
            )?;
            for (sender, streams) in [
                ("client", &connection.client),
                ("server", &connection.server),
            ] {
                write_stdout_line(
                    invocation,
                    format_args!("  {sender} QPACK inserts={}", streams.encoder_inserts),
                )?;
                for issue in &streams.issues {
                    render_issue(invocation, issue)?;
                }
            }
        }
        Event::Exchange { exchange } => {
            write_stdout_line(
                invocation,
                format_args!(
                    "  Exchange connection={} stream={}",
                    exchange.connection, exchange.stream
                ),
            )?;
            side(invocation, "Request", exchange.request.as_ref())?;
            side(invocation, "Response", exchange.response.as_ref())?;
        }
    }
    Ok(())
}

fn side(invocation: &Invocation, label: &str, side: Option<&Side>) -> Result<(), CliError> {
    let Some(side) = side else {
        return write_stdout_line(invocation, format_args!("    {label} missing from capture"));
    };
    write_stdout_line(
        invocation,
        format_args!(
            "    {label} DATA frames={} bytes={} complete={}",
            side.data_frames, side.data_bytes, side.complete
        ),
    )?;
    for section in &side.header_sections {
        let kind = section.kind;
        let offset = section.offset;
        let coding = match section.required_insert_count {
            Some(0) => "static/literal",
            Some(_) => "dynamic (fits captured history)",
            None => "undecoded",
        };
        match (&section.method, section.status) {
            (Some(method), _) => write_stdout_line(
                invocation,
                format_args!("      {kind} {method} offset={offset} QPACK={coding}"),
            ),
            (_, Some(status)) => write_stdout_line(
                invocation,
                format_args!("      {kind} {status} offset={offset} QPACK={coding}"),
            ),
            _ => write_stdout_line(
                invocation,
                format_args!("      {kind} offset={offset} QPACK={coding}"),
            ),
        }?;
        for field in &section.fields {
            let name = field.name.escape_default();
            match (&field.value, &field.value_hex) {
                (Some(value), _) => write_stdout_line(
                    invocation,
                    format_args!("        {name} = \"{}\"", value.escape_default()),
                ),
                (_, Some(value)) => {
                    write_stdout_line(invocation, format_args!("        {name} = hex:{value}"))
                }
                _ => write_stdout_line(invocation, format_args!("        {name}")),
            }?;
        }
    }
    for issue in &side.issues {
        render_issue(invocation, issue)?;
    }
    Ok(())
}

fn render_issue(invocation: &Invocation, issue: &Issue) -> Result<(), CliError> {
    let code = issue.code;
    match issue.offset {
        Some(offset) => write_stdout_line(invocation, format_args!("      {code} offset={offset}")),
        None => write_stdout_line(invocation, format_args!("      {code}")),
    }
}

pub(super) fn summary(invocation: &Invocation, terminal: &Terminal) -> Result<(), CliError> {
    let summary = &terminal.summary;
    write_stdout_line(
        invocation,
        format_args!(
            "HTTP/3 connections={} exchanges={} unknown_alpn={} skipped_alpn={} input_incomplete={}",
            summary.connections,
            summary.exchanges,
            summary.unknown_alpn,
            summary.skipped_alpn,
            summary.input_incomplete
        ),
    )
}
