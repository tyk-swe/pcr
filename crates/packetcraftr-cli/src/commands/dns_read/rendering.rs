// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Captured names reach the terminal only through the sanitizing writer.

use std::net::SocketAddr;

use crate::output::dns_read::Latency;

use crate::errors::CliError;
use crate::output::dns_read as wire;
use crate::rendering::{
    comma_separated, optional_display, render_dns_fields, write_stdout_line, write_summary_line,
};

pub(super) fn render_message(message: &wire::Message) -> Result<(), CliError> {
    let flow = &message.flow.flow;
    write_stdout_line(format_args!(
        "DNS {}:{} message={} status={} {} -> {} frames={}",
        message.transport,
        message.stream,
        message.index,
        message.status,
        SocketAddr::new(flow.source, flow.source_port),
        SocketAddr::new(flow.destination, flow.destination_port),
        frames(&message.sources),
    ))?;
    if let Some(fields) = &message.fields {
        render_dns_fields(fields)?;
    }
    if let Some(error) = &message.error {
        write_stdout_line(format_args!("  error: {error}"))?;
    }
    Ok(())
}

pub(super) fn render_transaction(transaction: &wire::Transaction) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "  transaction id={} status={} queries={} response={} latest_latency={}",
        transaction.dns_id,
        transaction.status,
        or_none(comma_separated(&transaction.queries)),
        optional_display(transaction.response),
        optional_display(transaction.latest_query_latency.map(latency)),
    ))
}

pub(super) fn render_issue(issue: &wire::Issue) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "  TCP stream={} frame={} status={}",
        issue.stream, issue.number, issue.status,
    ))
}

pub(super) fn render_complete(complete: &wire::Complete) -> Result<(), CliError> {
    write_summary_line(format_args!(
        "{} DNS messages; {} matched and {} unanswered transactions in {} captured frames",
        complete.summary.messages,
        complete.summary.matched_transactions,
        complete.summary.unanswered_transactions,
        complete.frames_read
    ))
}

fn frames(sources: &[crate::output::provenance::Source]) -> String {
    or_none(comma_separated(sources.iter().map(|source| source.number)))
}

fn or_none(list: String) -> String {
    if list.is_empty() {
        "none".to_owned()
    } else {
        list
    }
}

fn latency(latency: Latency) -> String {
    let sign = if latency.negative { "-" } else { "" };
    format!("{sign}{}ns", latency.nanoseconds)
}
