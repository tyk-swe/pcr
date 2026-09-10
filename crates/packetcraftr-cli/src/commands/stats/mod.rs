// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use packetcraftr_cli::output::contract::Format;

use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_core::analysis;

use packetcraftr_cli::output;

use self::arguments::Args;
use super::offline_analysis::{omitted_diagnostic, prepare};
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::emit_aggregate;
use packetcraftr_cli::output::stats::Table;

pub(super) fn run(arguments: Args, format: Format) -> Result<(), CliError> {
    // Stats assigns conversation indices, so stream-aware filters like
    // `tcp.stream == 7` are supported here.
    let prepared = prepare(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.decode,
    )?;
    let mut collector = analysis::stats::Collector::for_table(
        Duration::from_millis(arguments.interval_ms),
        arguments.table.into(),
    )
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
        Format::Text => rendering::render_text(arguments.table, &report, frames_read, &diagnostics),
        Format::Json => {
            let result =
                output::stats::Report::try_from_report(arguments.table, report, frames_read)
                    .map_err(CliError::classified)?;
            emit_aggregate(output::contract::Command::Stats, result, diagnostics)
        }
        _ => unreachable!("command dispatch validated the output format"),
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
        let omitted = u64::try_from(rows.len().saturating_sub(limit)).unwrap_or(u64::MAX);
        rows.truncate(limit);
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
