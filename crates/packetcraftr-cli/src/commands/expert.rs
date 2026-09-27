// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use crate::output::contract::ToolFormat;

use packetcraftr_core::analysis::{self, expert::gate};
use packetcraftr_core::error::BoundaryError;

use self::arguments::Args;
use super::CommandExit;
use super::offline_analysis::prepare;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::output;
use crate::rendering::StreamEncoder;

/// The process status when the analysis completed and published its report
/// but the verdict was not `pass`. `fail` and `inconclusive` share this code;
/// the report's `verdict` field distinguishes them.
const VERDICT_NOT_PASS: u8 = 1;

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(true),
        );
        settings.retained_result_items(self.limits.capture.max_frames);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<CommandExit, CliError> {
        run(self, format, stream)
    }
}

pub(super) fn run(
    arguments: Args,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<CommandExit, CliError> {
    let prepared = prepare(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.decode,
    )?;
    // The gate's criteria are analysis criteria validated before input opens,
    // not resource ceilings.
    let mut gate = arguments
        .fail_on
        .map(|min_severity| {
            gate::Gate::new(gate::Options {
                min_severity: min_severity.into(),
                allow_findings: arguments.allow_findings.unwrap_or(0),
                minimum_frames: arguments.minimum_frames.unwrap_or(1),
            })
            .map_err(BoundaryError::from_error)
        })
        .transpose()
        .map_err(CliError::classified)?;
    let mut reader = open_capture(&arguments.path, arguments.limits.capture.reader)?;

    // The collector declares what expert reads: transport indexes, the
    // reassembler's byte-exact retransmission evidence, and reconstructed-
    // datagram diagnostics.
    let session = analysis::Session::new(
        prepared.registry.clone(),
        prepared.options(),
        analysis::expert::Collector::new(),
        None,
    );
    let mut state = rendering::State::new(arguments.limits.capture.retention_ceiling());
    let selector = analysis::expert::Selector {
        min_severity: arguments.min_severity.into(),
        codes: arguments.codes,
    };
    let outcome = session
        .run(
            &mut reader,
            super::offline_analysis::ip_event_sink(format, stream),
            |finding| {
                // The gate observes every produced finding — including ones
                // the report selector or retention discards, and the trailing
                // findings the collector emits at end of input — before the
                // selector applies.
                if let Some(gate) = gate.as_mut() {
                    gate.observe(&finding).map_err(BoundaryError::from_error)?;
                }
                if selector.matches(&finding) {
                    state.count(&finding);
                    rendering::render_record(format, finding.into(), &mut state, stream)
                        .map_err(CliError::into_boundary_error)?;
                }
                Ok(())
            },
        )
        .map_err(CliError::classified)?;
    let summary = outcome.run;
    let gate = gate.map(|gate| gate.finish(summary.frames_matched));
    // The verdict's status is fixed once the analysis completes; a
    // publication failure below still overrides it.
    let exit = match gate.as_ref().map(|report| report.verdict) {
        Some(gate::Verdict::Fail | gate::Verdict::Inconclusive) => {
            CommandExit::status(VERDICT_NOT_PASS)
        }
        _ => CommandExit::SUCCESS,
    };
    let gate = gate.map(output::expert::GateReport::from);

    match format {
        ToolFormat::Text => rendering::render_text(&summary, &state, gate.as_ref()),
        ToolFormat::Json => rendering::render_aggregate(&summary, state, gate),
        ToolFormat::Ndjson => rendering::render_stream(&summary, state, stream, gate),
    }?;
    Ok(exit)
}
