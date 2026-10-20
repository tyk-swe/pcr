// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bodies are counted and discarded, never retained.

pub(in crate::commands) mod arguments;
mod rendering;

use packetcraftr_core::analysis::http::{Collector, Event};

use self::arguments::Args;
use crate::commands::offline_analysis::{
    Inspection, complete_application, inspect, require_tcp_stream,
};
use crate::errors::CliError;
use crate::output::{
    contract::{Command, Format},
    http as wire,
};
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
        crate::resources::declare!(settings, self, [max_http_body_bytes: Bytes @ Operation]);
        self.application.resources(settings);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(true),
        );
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

fn run(
    invocation: &crate::invocation::Invocation,
    args: Args,
    format: Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    args.application.validate_output()?;
    let mut ports = args.http_ports;
    ports.extend([80, 8080]);
    let collector = Collector::new(args.application.core(), ports, args.max_http_body_bytes)
        .map_err(CliError::classified)?;
    let selector = require_tcp_stream(args.stream.as_ref(), "HTTP/1")?;
    let (mut messages, mut issues) = (Vec::new(), Vec::new());
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
        |output, event| match event {
            Event::Message(message) => output.emit(
                wire::Message::try_from(*message).map_err(CliError::classified)?,
                &mut messages,
                |invocation, message| {
                    rendering::render_message(invocation, message, stream.presentation())
                },
            ),
            Event::Issue(issue) => output.emit(
                wire::Issue::from(issue),
                &mut issues,
                rendering::render_issue,
            ),
        },
    )?;
    let complete = wire::Complete::try_from((&outcome.run, outcome.summary, outcome.scopes))
        .map_err(CliError::classified)?;
    complete_application(
        invocation,
        Command::Http,
        format,
        stream,
        complete,
        |complete| wire::Report::from((messages, issues, complete)),
        rendering::render_complete,
    )
}
