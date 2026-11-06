// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
pub(in crate::commands) mod output;
mod rendering;

use packetcraftr_core::analysis::dns::{Collector, Event};

use self::arguments::Args;
use self::output as wire;
use crate::commands::offline_analysis::{Inspection, complete_application, inspect};
use crate::errors::CliError;
use crate::output::contract::Command;

use crate::output::contract::PublishedType;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "dnsAnalysisSuccess",
            command: "dns-read",
            rust_types: &["crate::commands::analyze::dns::output::Report"],
            events: &[],
            example: "examples/documents/output-dns-read-success.json",
        },
        PublishedType {
            definition: "dnsAnalysisStreamSuccess",
            command: "dns-read",
            rust_types: &[
                "crate::commands::analyze::dns::output::Issue",
                "crate::commands::analyze::dns::output::Message",
                "crate::commands::analyze::dns::output::Report",
                "crate::commands::analyze::dns::output::Transaction",
                "crate::commands::offline_analysis::output::reassembly::Event",
            ],
            events: &[
                "complete",
                "dns_message",
                "dns_stream_issue",
                "dns_transaction",
                "ip_datagram_completed",
                "ip_datagram_incomplete",
                "ip_overlap_resolved",
            ],
            example: "examples/documents/output-dns-read-complete.json",
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
    let application = args.application.limits()?;
    let mut ports = args.dns_ports;
    ports.push(53);
    let collector = Collector::new(application.core(), ports).map_err(CliError::classified)?;
    let (mut messages, mut transactions, mut issues) = (Vec::new(), Vec::new(), Vec::new());
    let outcome = inspect(
        invocation,
        Inspection {
            path: &args.path,
            limits: args.limits,
            decode: &args.decode,
            application,
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
