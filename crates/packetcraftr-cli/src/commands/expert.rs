// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use crate::output::contract::ToolFormat;

use packetcraftr_core::analysis;

use self::arguments::{Args, Severity};
use super::offline_analysis::prepare;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::StreamEncoder;

fn matches_selector(
    finding: &analysis::expert::Finding,
    min_severity: Severity,
    codes: &[String],
) -> bool {
    if finding.severity < min_severity.into() {
        return false;
    }
    if !codes.is_empty() && !codes.iter().any(|c| c == finding.code) {
        return false;
    }
    true
}

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.limits.duration.max_duration())
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
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    arguments: Args,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let prepared = prepare(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.decode,
    )?;
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
    let min_severity = arguments.min_severity;
    let codes = &arguments.codes;
    let outcome = session
        .run(
            &mut reader,
            super::offline_analysis::ip_event_sink(format, stream),
            |finding| {
                if matches_selector(&finding, min_severity, codes) {
                    state.count(&finding);
                    rendering::render_record(format, finding.into(), &mut state, stream)
                        .map_err(CliError::into_boundary_error)?;
                }
                Ok(())
            },
        )
        .map_err(CliError::classified)?;
    let summary = outcome.run;

    match format {
        ToolFormat::Text => rendering::render_text(&summary, &state),
        ToolFormat::Json => rendering::render_aggregate(&summary, state),
        ToolFormat::Ndjson => rendering::render_stream(&summary, state, stream),
    }
}
