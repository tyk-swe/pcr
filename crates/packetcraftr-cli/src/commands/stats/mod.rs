// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use std::time::Duration;

use packetcraftr::{analysis, output};

use self::arguments::Args;
use super::format::AggregateFormat;
use super::offline_analysis::prepare;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::emit_aggregate;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = AggregateFormat::narrow(output::contract::Command::Stats, format)?;
    // Stats assigns conversation indices, so stream-aware filters like
    // `tcp.stream == 7` are supported here.
    let prepared = prepare(arguments.limits, arguments.filter.as_deref())?;
    let mut collector =
        analysis::stats::Collector::new(Duration::from_millis(arguments.interval_ms))
            .map_err(CliError::classified)?;

    let mut reader = open_capture(&arguments.path, arguments.limits.capture.reader_bounds())?;

    let options = prepared.options(false);
    let summary = analysis::run(&mut reader, prepared.registry.clone(), &options, |record| {
        collector.observe(&record);
        Ok(())
    })
    .map_err(CliError::classified)?;
    let report = collector.finish(&summary);
    let frames_read = summary.frames_read;

    match format {
        AggregateFormat::Text => rendering::render_text(arguments.table, &report, frames_read),
        AggregateFormat::Json => {
            let result = output::stats::Report::try_from_report(
                arguments.table.into(),
                &report,
                frames_read,
            )
            .map_err(CliError::classified)?;
            emit_aggregate(output::contract::Command::Stats, result, Vec::new())
        }
    }
}
