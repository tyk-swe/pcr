// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `dns-read`: inspects the DNS messages captured on UDP flows and TCP
//! streams and pairs queries with responses into transactions.

pub(super) mod arguments;
mod rendering;

use packetcraftr_core::analysis::dns::{Collector, Event};

use self::arguments::Args;
use super::offline_analysis::{Inspection, inspect};
use crate::errors::CliError;
use crate::output::{
    contract::{Command, ToolFormat},
    dns_read as wire,
};
use crate::rendering::{StreamEncoder, emit_aggregate};

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.limits.duration.max_duration())
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
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

fn run(args: Args, format: ToolFormat, stream: &StreamEncoder) -> Result<(), CliError> {
    args.application.validate_output()?;
    let mut ports = args.dns_ports;
    ports.push(53);
    let collector = Collector::new(args.application.core(), ports).map_err(CliError::classified)?;
    let (mut messages, mut transactions, mut issues) = (Vec::new(), Vec::new(), Vec::new());
    let outcome = inspect(
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
        format,
        stream,
        |output, event| match event {
            Event::Message(value) => output.emit(
                wire::Message::try_from(*value).map_err(CliError::classified)?,
                &mut messages,
                rendering::render_message,
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
    match format {
        ToolFormat::Json => emit_aggregate(
            Command::DnsRead,
            wire::Report::from((messages, transactions, issues, complete)),
            Vec::new(),
        ),
        ToolFormat::Ndjson => stream.complete(complete, Vec::new()).map_err(Into::into),
        ToolFormat::Text => rendering::render_complete(&complete),
    }
}
