// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
mod rendering;

use packetcraftr_core::analysis::dns::{Collector, Event};

use self::arguments::Args;
use crate::commands::offline_analysis::{Inspection, complete_application, inspect};
use crate::errors::CliError;
use crate::output::{contract::Command, dns_read as wire};

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
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn run(invocation: &crate::invocation::Invocation, args: Args) -> Result<(), CliError> {
    let stream = &invocation.output;
    args.application.validate_output()?;
    let mut ports = args.dns_ports;
    ports.push(53);
    let collector = Collector::new(args.application.core(), ports).map_err(CliError::classified)?;
    let (mut messages, mut transactions, mut issues) = (Vec::new(), Vec::new(), Vec::new());
    let outcome = inspect(
        invocation,
        Inspection {
            path: &args.path,
            limits: args.limits,
            decode: &args.decode,
            application: args.application,
            selector: args
                .stream
                .as_ref()
                .map(crate::command_options::Selector::get)
                .transpose()?,
        },
        collector,
        |output, event| match event {
            Event::Message(value) => output.emit(
                wire::Message::try_from(*value).map_err(CliError::classified)?,
                &mut messages,
                |invocation, message| {
                    rendering::render_message(invocation, message, stream.presentation())
                },
            ),
            Event::Transaction(value) => output.emit(
                wire::Transaction::try_from(value).map_err(CliError::classified)?,
                &mut transactions,
                rendering::render_transaction,
            ),
            Event::Issue(value) => output.emit(
                wire::Issue::from(value),
                &mut issues,
                rendering::render_issue,
            ),
        },
    )?;
    let complete = wire::Complete::try_from((&outcome.run, outcome.summary, outcome.scopes))
        .map_err(CliError::classified)?;
    complete_application(
        invocation,
        Command::DnsRead,
        complete,
        |complete| wire::Report::from((messages, transactions, issues, complete)),
        rendering::render_complete,
    )
}
