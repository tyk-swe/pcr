// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
pub(in crate::commands) mod output;
mod rendering;

use crate::output::contract::Format;

use packetcraftr_core::analysis;

use self::arguments::Args;
use crate::commands::offline_analysis::prepare;
use crate::errors::CliError;
use crate::input::open_capture;

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "expertSuccess",
            command: "expert",
            rust_types: &["crate::commands::analyze::expert::output::Report"],
            events: &[],
            example: "examples/documents/output-expert-complete.json",
        },
        PublishedType {
            definition: "expertStreamSuccess",
            command: "expert",
            rust_types: &[
                "crate::commands::analyze::expert::output::Finding",
                "crate::commands::analyze::expert::output::Report",
                "crate::commands::offline_analysis::output::reassembly::Event",
            ],
            events: &[
                "complete",
                "finding",
                "ip_datagram_completed",
                "ip_datagram_incomplete",
                "ip_overlap_resolved",
            ],
            example: "examples/documents/output-expert-complete.json",
        },
    ];
    const FORMATS: &'static [crate::output::contract::Format] =
        crate::output::contract::TEXT_JSON_NDJSON;
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
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
) -> Result<(), CliError> {
    let format = invocation.format;
    let stream = &invocation.output;
    let prepared = prepare(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.decode,
    )?;
    let mut reader = open_capture(
        &invocation.control,
        &invocation.output,
        &arguments.path,
        prepared.capture_limits,
    )?;

    let session = analysis::Session::new(
        prepared.registry.clone(),
        prepared.session_options(invocation),
        analysis::expert::Collector::default(),
    );
    let mut state = rendering::State::new(prepared.capture_limits.retention_ceiling());
    let selector = analysis::expert::Selector {
        min_severity: arguments.min_severity.into(),
        codes: arguments.codes,
    };
    let outcome = session
        .run(
            &mut reader,
            crate::commands::offline_analysis::ip_event_sink(format, stream),
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
