// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use packetcraftr::{analysis, output};

use self::arguments::{Args, Severity};
use super::super::errors::CliError;
use super::super::input::open_capture;
use super::format::ToolFormat;
use super::offline_analysis::{Prepared, prepare};
use crate::rendering::StreamEncoder;

fn matches_selector(
    finding: &analysis::expert::Finding,
    min_severity: Severity,
    codes: &[String],
) -> bool {
    if Severity::from(finding.severity) < min_severity {
        return false;
    }
    if !codes.is_empty() && !codes.iter().any(|c| c == &finding.code) {
        return false;
    }
    true
}

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    let format = ToolFormat::narrow(output::contract::Command::Expert, format)?;
    let Prepared {
        registry,
        filter,
        limits,
    } = prepare(arguments.limits, arguments.filter.as_deref())?;
    let mut reader = open_capture(&arguments.path, arguments.limits.capture)?;

    let options = analysis::Options {
        filter: filter.as_ref(),
        // Expert needs the reassembler's byte-exact retransmission evidence.
        tcp_events: true,
        limits,
    };
    let mut collector = analysis::expert::Collector::new();
    let mut state = rendering::State::default();
    let outcome = analysis::run(&mut reader, registry, &options, |record| {
        for finding in collector.observe(&record) {
            if matches_selector(&finding, arguments.min_severity, &arguments.codes) {
                state.count(&finding);
                rendering::render_record(format, finding.into(), &mut state, stream)
                    .map_err(CliError::into_boundary_error)?;
            }
        }
        Ok(())
    });
    let summary = outcome.map_err(CliError::classified)?;
    let (trailing, _expert_summary) =
        collector.finish(&summary.trailing_tcp_events, summary.frames_read);
    for finding in trailing {
        if matches_selector(&finding, arguments.min_severity, &arguments.codes) {
            state.count(&finding);
            rendering::render_record(format, finding.into(), &mut state, stream)?;
        }
    }

    match format {
        ToolFormat::Text => rendering::render_text(&summary, &state),
        ToolFormat::Json => rendering::render_aggregate(&summary, state),
        ToolFormat::Ndjson => rendering::render_stream(&summary, state, stream),
    }
}
