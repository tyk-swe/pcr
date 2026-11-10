// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
mod csv;
pub(in crate::commands) mod output;
mod rendering;
mod selection;

use crate::output::contract::Format;
use crate::output::envelope::Published;

use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_core::analysis;

use self::arguments::Args;
use self::output::Table;
use crate::commands::offline_analysis::prepare;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::publication::emit_published;

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[PublishedType {
        definition: "statsSuccess",
        command: "stats",
        rust_types: &["crate::commands::analyze::stats::output::Report"],
        events: &[],
        example: "examples/documents/output-stats-clock.json",
    }];
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Csv,
    ];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        settings.declare(crate::resources::Field {
            id: "top",
            value: crate::resources::SettingValue::setting_value(&self.effective_top()),
            unit: crate::resources::Unit::Count,
            stage: crate::resources::Stage::ResultRetention,
            enabled: (self.table != arguments::Table::Fragments).into(),
            preset: None,
        });
        crate::resources::declare!(settings, self, [
            min_frames: Count @ ResultRetention if self.table != arguments::Table::Fragments,
        ]);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(false),
        );
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
) -> Result<(), CliError> {
    let format = invocation.format;
    let presentation = invocation.output.presentation();
    arguments.validate_selection()?;
    let table = Table::from(arguments.table);
    if format == Format::Csv && matches!(table, Table::Overview | Table::Fragments) {
        return Err(CliError::new(
            core::error::Kind::Usage,
            "CSV supports only conversations, endpoints, protocols, ports, and io tables",
        ));
    }
    let top = arguments.effective_top();
    let aggregation = analysis::stats::Table::from(arguments.table);
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

    let mut reader = open_capture(
        &invocation.control,
        &invocation.output,
        &arguments.path,
        prepared.capture_limits,
    )?;

    let options = prepared.options(invocation);
    let summary = analysis::run(&mut reader, prepared.registry.clone(), &options, |record| {
        collector.observe(&record);
        Ok(())
    })
    .map_err(CliError::classified)?;
    let mut report = collector.finish(&summary);
    let frames_read = summary.frames_read;
    invocation.check()?;
    let diagnostics = selection::select(
        &mut report,
        table,
        top,
        arguments.sort,
        arguments.min_frames,
    );
    invocation.check()?;

    match format {
        Format::Text => rendering::render_text(
            invocation,
            table,
            &report,
            frames_read,
            &diagnostics,
            presentation,
        ),
        Format::Json => {
            let result = output::Report::try_from((table, report, frames_read))
                .map_err(CliError::classified)?;
            emit_published(
                invocation,
                crate::output::contract::Command::Stats,
                Published::new(result, diagnostics),
            )
        }
        Format::Csv => {
            let result = output::Report::try_from((table, report, frames_read))
                .map_err(CliError::classified)?;
            csv::render(invocation, &result)?;
            crate::terminal::render_diagnostics_stderr(&diagnostics)
        }
        other => other.unreachable(),
    }
}
