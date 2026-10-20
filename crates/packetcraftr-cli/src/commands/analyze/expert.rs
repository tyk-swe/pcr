// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
mod rendering;

use crate::output::contract::Format;

use packetcraftr_core::analysis;

use self::arguments::Args;
use crate::commands::offline_analysis::prepare;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::StreamEncoder;

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
    ];
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
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let prepared = prepare(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.decode,
    )?;
    let mut reader = open_capture(invocation, &arguments.path, arguments.limits.capture.reader)?;

    let session = analysis::Session::new(
        prepared.registry.clone(),
        prepared.options(invocation),
        analysis::expert::Collector::new(),
    );
    let mut state = rendering::State::new(arguments.limits.capture.retention_ceiling());
    let selector = analysis::expert::Selector {
        min_severity: arguments.min_severity.into(),
        codes: arguments.codes,
    };
    let outcome = session
        .run(
            &mut reader,
            crate::rendering::ip_event_sink(format, stream),
            |finding| {
                if selector.matches(&finding) {
                    state.count(&finding);
                    rendering::render_record(
                        invocation,
                        format,
                        finding.into(),
                        &mut state,
                        stream,
                    )
                    .map_err(CliError::into_boundary_error)?;
                }
                Ok(())
            },
        )
        .map_err(CliError::classified)?;
    let summary = outcome.run;

    match format {
        Format::Text => rendering::render_text(invocation, &summary, &state),
        Format::Json => rendering::render_aggregate(invocation, &summary, state),
        Format::Ndjson => rendering::render_stream(&summary, state, stream),
        other => other.unreachable(),
    }
}
