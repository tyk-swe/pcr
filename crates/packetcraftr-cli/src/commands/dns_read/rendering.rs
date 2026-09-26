// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output::dns_read as wire;
use crate::rendering::write_plain_line;

pub(super) fn render_message(value: &wire::Message) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "DNS {:?}:{} message={} {:?} {}:{} -> {}:{} frames={:?} {}",
        value.transport,
        value.stream,
        value.index,
        value.status,
        value.flow.flow.source,
        value.flow.flow.source_port,
        value.flow.flow.destination,
        value.flow.flow.destination_port,
        value
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>(),
        value
            .fields
            .as_ref()
            .and_then(|fields| fields.get("questions"))
            .map(ToString::to_string)
            .unwrap_or_default()
    ))
}

pub(super) fn render_transaction(value: &wire::Transaction) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "  transaction id={} {:?} queries={:?} response={:?} latest_latency={:?}",
        value.dns_id, value.status, value.queries, value.response, value.latest_query_latency
    ))
}

pub(super) fn render_issue(value: &wire::Issue) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "  TCP stream={} frame={} {:?}",
        value.0.stream, value.0.number, value.0.status
    ))
}
