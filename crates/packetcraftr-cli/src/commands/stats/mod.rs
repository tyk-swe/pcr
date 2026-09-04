// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use std::time::Duration;

use packetcraftr::{analysis, core, output};

use self::arguments::{Args, Table};
use super::format::AggregateFormat;
use super::offline_analysis::{Retained, omitted_diagnostic, prepare_with_tls_ports};
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::emit_aggregate;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = AggregateFormat::narrow(output::contract::Command::Stats, format)?;
    // Stats assigns conversation indices, so stream-aware filters like
    // `tcp.stream == 7` are supported here.
    let prepared = prepare_with_tls_ports(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.tls_ports.ports,
    )?;
    let mut collector =
        analysis::stats::Collector::new(Duration::from_millis(arguments.interval_ms))
            .map_err(CliError::classified)?;

    let mut reader = open_capture(&arguments.path, arguments.limits.capture.reader)?;

    let options = prepared.options(false);
    let summary = analysis::run(&mut reader, prepared.registry.clone(), &options, |record| {
        collector.observe(&record);
        Ok(())
    })
    .map_err(CliError::classified)?;
    let mut report = collector.finish(&summary);
    let frames_read = summary.frames_read;
    let diagnostics = cap_table(&mut report, arguments.table, arguments.top);

    match format {
        AggregateFormat::Text => {
            rendering::render_text(arguments.table, &report, frames_read, &diagnostics)
        }
        AggregateFormat::Json => {
            let result = output::stats::Report::try_from_report(
                arguments.table.into(),
                &report,
                frames_read,
            )
            .map_err(CliError::classified)?;
            emit_aggregate(output::contract::Command::Stats, result, diagnostics)
        }
    }
}

/// Applies `--top` to the one table this run reports, so text and JSON render
/// the same rows and the same omission diagnostic. The fragments table is
/// bounded by `--max-ip-outcomes` instead.
fn cap_table(
    report: &mut analysis::stats::Report,
    table: Table,
    top: Option<usize>,
) -> Vec<core::diagnostic::Diagnostic> {
    let Some(limit) = top else {
        return Vec::new();
    };
    fn cap<T>(
        rows: &mut Vec<T>,
        limit: usize,
        code: &'static str,
        subject: &str,
    ) -> Vec<core::diagnostic::Diagnostic> {
        let mut retained = Retained::new(limit);
        for row in std::mem::take(rows) {
            retained.push(row);
        }
        let omitted = retained.omitted();
        *rows = retained.into_items();
        omitted_diagnostic(code, subject, omitted, "--top")
    }
    match table {
        Table::Conversations => cap(
            &mut report.conversations,
            limit,
            "stats.conversations_omitted",
            "conversation row(s)",
        ),
        Table::Endpoints => cap(
            &mut report.endpoints,
            limit,
            "stats.endpoints_omitted",
            "endpoint row(s)",
        ),
        Table::Protocols => cap(
            &mut report.protocols,
            limit,
            "stats.protocols_omitted",
            "protocol row(s)",
        ),
        Table::Ports => cap(
            &mut report.ports,
            limit,
            "stats.ports_omitted",
            "port row(s)",
        ),
        Table::Io => cap(&mut report.io, limit, "stats.io_omitted", "io bucket(s)"),
        Table::Fragments => Vec::new(),
    }
}
