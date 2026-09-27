// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `http`: inspects the cleartext HTTP/1 messages carried on captured TCP
//! streams. Bodies are counted and discarded — except `--body-message`,
//! whose one selected body `--write` stages, hashes, and publishes only
//! after the whole capture inspects cleanly and the message completes.

pub(super) mod arguments;
mod body;
mod rendering;

use packetcraftr_core::analysis::{
    StreamTransport,
    http::{Collector, Event},
};
use packetcraftr_core::error::Kind;

use self::arguments::Args;
use super::application_output::EventOutput;
use super::offline_analysis::{Inspection, inspect};
use crate::errors::CliError;
use crate::output::{
    contract::{Command, ToolFormat},
    http as wire,
    stream::PreparedComplete,
};
use crate::rendering::{PreparedAggregate, StreamEncoder, emit_aggregate, prepare_aggregate};
use crate::staged_output::StagedFile;

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
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
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

/// The terminal success record an artifact commit publishes unchanged:
/// converted, charged, and serialized before the commit boundary, then sent
/// once — and only — after it.
enum Prepared {
    Json(Box<PreparedAggregate<wire::Report>>),
    Ndjson(PreparedComplete),
    Text(Box<wire::Complete>),
}

fn run(args: Args, format: ToolFormat, stream: &StreamEncoder) -> Result<(), CliError> {
    args.application.validate_output()?;
    let mut ports = args.http_ports;
    ports.extend([80, 8080]);
    let collector = Collector::new(args.application.core(), ports, args.max_http_body_bytes)
        .map_err(CliError::classified)?;
    // Transaction collection closes on the first observe attempt, so the
    // flag must reach the collector before inspection starts.
    let collector = if args.transactions {
        collector
            .with_transactions()
            .map_err(CliError::classified)?
    } else {
        collector
    };
    let selector = args
        .stream
        .as_ref()
        .map(crate::command_options::Selector::get)
        .transpose()?;
    if selector.is_some_and(|selected| selected.transport != StreamTransport::Tcp) {
        return Err(CliError::new(
            Kind::Usage,
            "HTTP/1 inspection requires --stream tcp:INDEX",
        ));
    }
    // The destination stages before any input is read. The writer borrows
    // only the staged file; `selected` tracks the message's own evidence,
    // independently of the sink. The writer's borrow lives inside this block,
    // so `staged` is movable once `seal` ends it and the block closes.
    let mut staged = args.write.as_deref().map(StagedFile::stage).transpose()?;
    let mut selected = args.body_message.map(body::SelectedMessage::new);
    let mut output = EventOutput::new(
        format,
        stream,
        args.application.max_application_output_bytes,
    );
    let prepared = {
        let mut writer = staged.as_mut().map(|staged| {
            let destination = staged.destination().to_owned();
            body::BodyWriter::new(staged.as_file_mut(), destination)
        });
        let collector = match (args.body_message, writer.as_mut()) {
            (Some(message), Some(writer)) => collector
                .with_body_sink(message, writer)
                .map_err(CliError::classified)?,
            _ => collector,
        };
        let (mut messages, mut transactions, mut issues) = (Vec::new(), Vec::new(), Vec::new());
        let outcome = inspect(
            Inspection {
                path: &args.path,
                limits: args.limits,
                decode: &args.decode,
                selector,
            },
            collector,
            format,
            stream,
            &mut output,
            |output, event| {
                if let Some(selected) = &mut selected {
                    selected.observe(&event);
                }
                match event {
                    Event::Message(message) => output.emit(
                        wire::Message::try_from(*message).map_err(CliError::classified)?,
                        &mut messages,
                        rendering::render_message,
                    ),
                    Event::Issue(issue) => output.emit(
                        wire::Issue::from(issue),
                        &mut issues,
                        rendering::render_issue,
                    ),
                    Event::Transaction(transaction) => output.emit(
                        wire::Transaction::try_from(*transaction).map_err(CliError::classified)?,
                        &mut transactions,
                        rendering::render_transaction,
                    ),
                }
            },
        )?;
        let mut complete =
            wire::Complete::try_from((&outcome.run, outcome.summary, outcome.scopes))
                .map_err(CliError::classified)?;
        let Some(writer) = writer else {
            return match format {
                ToolFormat::Json => emit_aggregate(
                    Command::Http,
                    wire::Report::from((messages, transactions, issues, complete)),
                    Vec::new(),
                ),
                ToolFormat::Ndjson => stream.complete(complete, Vec::new()).map_err(Into::into),
                ToolFormat::Text => rendering::render_complete(&complete),
            };
        };
        // The whole capture inspected cleanly through EOF. Only now may the
        // selected evidence admit an artifact, the artifact record charge the
        // shared output allowance once, and the success report freeze —
        // before the commit boundary touches the filesystem.
        let export = selected
            .expect("a staged writer implies a selected message")
            .artifact(
                writer.bytes(),
                writer.sha256(),
                writer.destination().display().to_string(),
            )?;
        output.charge(&export)?;
        complete.body_export = Some(export);
        let prepared = match format {
            ToolFormat::Json => Prepared::Json(Box::new(prepare_aggregate(
                Command::Http,
                wire::Report::from((messages, transactions, issues, complete)),
                Vec::new(),
            )?)),
            ToolFormat::Ndjson => Prepared::Ndjson(
                stream
                    .prepare_complete(complete, Vec::new())
                    .map_err(CliError::from)?,
            ),
            ToolFormat::Text => Prepared::Text(Box::new(complete)),
        };
        // The commit's first step flushes the buffered tail into the staged
        // file and ends the borrow, so the file itself can commit next.
        writer.seal()?;
        prepared
    };
    // Commit: sync, recheck the deadline, and publish without clobbering.
    body::commit(staged.expect("a staged writer implies a staged file"))?;
    match prepared {
        Prepared::Json(aggregate) => aggregate.publish(),
        Prepared::Ndjson(prepared) => stream
            .publish_prepared_complete(prepared)
            .map_err(Into::into),
        Prepared::Text(complete) => {
            rendering::render_body_export(&complete)?;
            rendering::render_complete(&complete)
        }
    }
}
