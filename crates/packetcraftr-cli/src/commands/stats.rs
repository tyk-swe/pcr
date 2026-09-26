// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use crate::output::contract::AggregateFormat;

use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_core::analysis;

use crate::output;

use self::arguments::Args;
use super::offline_analysis::{omitted_diagnostic, prepare};
use crate::errors::CliError;
use crate::input::open_capture;
use crate::output::stats::Table;
use crate::rendering::emit_aggregate;

impl super::Spec for Args {
    type Format = crate::output::contract::AggregateFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [top: Count @ ResultRetention]);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(false),
        );
    }

    fn run(
        self,
        format: Self::Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: AggregateFormat) -> Result<(), CliError> {
    let table = Table::from(arguments.table);
    let aggregation = analysis::stats::Table::from(arguments.table);
    // Stats assigns conversation indices, so stream-aware filters like
    // `tcp.stream == 7` are supported here.
    let prepared = prepare(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.decode,
    )?;
    let mut collector = analysis::stats::Collector::for_table(
        Duration::from_millis(arguments.interval_ms),
        aggregation,
    )
    .map_err(CliError::classified)?;

    let mut reader = open_capture(&arguments.path, arguments.limits.capture.reader)?;

    let options = prepared.options();
    let summary = analysis::run(&mut reader, prepared.registry.clone(), &options, |record| {
        collector.observe(&record);
        Ok(())
    })
    .map_err(CliError::classified)?;
    let mut report = collector.finish(&summary);
    let frames_read = summary.frames_read;
    let diagnostics = cap_table(&mut report, table, arguments.top);

    match format {
        AggregateFormat::Text => rendering::render_text(table, &report, frames_read, &diagnostics),
        AggregateFormat::Json => {
            let result = output::stats::Report::try_from((table, report, frames_read))
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
    let Some(limit) = top else {
        return Vec::new();
    };
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
