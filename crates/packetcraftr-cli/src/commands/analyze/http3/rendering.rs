// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::invocation::Invocation;
use crate::terminal::{push_stdout_line, write_stdout_line};

use super::output::{Event, Issue, Side, Terminal};

pub(super) fn event(event: &Event) -> String {
    let mut block = String::new();
    match event {
        Event::Connection { connection } => {
            push_stdout_line(
                &mut block,
                &format!(
                    "HTTP/3 connection={} QUIC version={:#010x} capture frames={}..{} transport_incomplete={}",
                    connection.connection,
                    connection.version,
                    connection.first_frame,
                    connection.last_frame,
                    connection.transport_incomplete
                ),
            );
            for (sender, streams) in [
                ("client", &connection.client),
                ("server", &connection.server),
            ] {
                push_stdout_line(
                    &mut block,
                    &format!("  {sender} QPACK inserts={}", streams.encoder_inserts),
                );
                for issue in &streams.issues {
                    render_issue(&mut block, issue);
                }
            }
        }
        Event::Exchange { exchange } => {
            push_stdout_line(
                &mut block,
                &format!(
                    "  Exchange connection={} stream={}",
                    exchange.connection, exchange.stream
                ),
            );
            side(&mut block, "Request", exchange.request.as_ref());
            side(&mut block, "Response", exchange.response.as_ref());
        }
    }
    block
}

fn side(block: &mut String, label: &str, side: Option<&Side>) {
    let Some(side) = side else {
        push_stdout_line(block, &format!("    {label} missing from capture"));
        return;
    };
    push_stdout_line(
        block,
        &format!(
            "    {label} DATA frames={} bytes={} complete={}",
            side.data_frames, side.data_bytes, side.complete
        ),
    );
    for section in &side.header_sections {
        let kind = section.kind;
        let offset = section.offset;
        let coding = match section.required_insert_count {
            Some(0) => "static/literal",
            Some(_) => "dynamic (fits captured history)",
            None => "undecoded",
        };
        match (&section.method, section.status) {
            (Some(method), _) => push_stdout_line(
                block,
                &format!("      {kind} {method} offset={offset} QPACK={coding}"),
            ),
            (_, Some(status)) => push_stdout_line(
                block,
                &format!("      {kind} {status} offset={offset} QPACK={coding}"),
            ),
            _ => push_stdout_line(
                block,
                &format!("      {kind} offset={offset} QPACK={coding}"),
            ),
        }
        for field in &section.fields {
            let name = field.name.escape_default();
            match (&field.value, &field.value_hex) {
                (Some(value), _) => push_stdout_line(
                    block,
                    &format!("        {name} = \"{}\"", value.escape_default()),
                ),
                (_, Some(value)) => {
                    push_stdout_line(block, &format!("        {name} = hex:{value}"));
                }
                _ => push_stdout_line(block, &format!("        {name}")),
            }
        }
    }
    for issue in &side.issues {
        render_issue(block, issue);
    }
}

fn render_issue(block: &mut String, issue: &Issue) {
    let code = issue.code;
    match issue.offset {
        Some(offset) => push_stdout_line(block, &format!("      {code} offset={offset}")),
        None => push_stdout_line(block, &format!("      {code}")),
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
