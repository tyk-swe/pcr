// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use packetcraftr_core::analysis::StreamTransport;
use packetcraftr_core::analysis::quic::Collector;

use self::arguments::Args;
use super::offline_analysis::{Inspection, complete_application, inspect};
use crate::errors::CliError;
use crate::output::{contract::Command, quic as wire};
use crate::rendering::StreamEncoder;

impl super::Spec for Args {
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
        self.application.resources(settings);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(false),
        );
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<super::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

fn run(
    invocation: &crate::invocation::Invocation,
    args: Args,
    format: crate::output::contract::Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    args.application.validate_output()?;
    let selector = args
        .stream
        .as_ref()
        .map(crate::command_options::Selector::get)
        .transpose()?;
    if selector.is_some_and(|selected| selected.transport != StreamTransport::Udp) {
        return Err(CliError::new(
            packetcraftr_core::error::Kind::Usage,
            "quic inspection requires --stream udp:INDEX",
        ));
    }
    let limits = args.limits();
    let collector = Collector::new(args.quic_ports, limits).map_err(CliError::classified)?;
    let mut conversations = Vec::new();
    let outcome = inspect(
        invocation,
        Inspection {
            path: &args.path,
            limits: args.limits,
            decode: &args.decode,
            application: args.application,
            selector,
        },
        collector,
        format,
        stream,
        |output, event| {
            output.emit(
                wire::Conversation::try_from(event).map_err(CliError::classified)?,
                &mut conversations,
                rendering::render_conversation,
            )
        },
    )?;
    let complete = wire::Summary::from((outcome.summary, &outcome.run));
    complete_application(
        invocation,
        Command::Quic,
        format,
        stream,
        complete,
        |complete| wire::Report::from((conversations, complete)),
        rendering::render_summary,
    )
}
