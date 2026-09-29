// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Optional entity export streams body bytes into staged files.

pub(super) mod arguments;
mod export;
mod rendering;

use packetcraftr_core::analysis::{
    StreamTransport,
    http::{Collector, Event},
};
use packetcraftr_core::error::Kind;

use self::arguments::Args;
use super::offline_analysis::{Inspection, inspect};
use crate::errors::CliError;
use crate::output::{
    contract::{Command, ToolFormat},
    http as wire,
};
use crate::rendering::{StreamEncoder, emit_aggregate};

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_http_body_bytes: Bytes @ Operation, max_http_export_bytes: Bytes @ CaptureStorage]);
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
    let mut ports = args.http_ports;
    ports.extend([80, 8080]);
    let mut export = args
        .write
        .as_deref()
        .map(|path| {
            export::Export::new(
                path,
                args.decode_content,
                args.max_http_export_bytes,
                args.max_http_body_bytes,
            )
        })
        .transpose()?;
    let collector = Collector::new(args.application.core(), ports, args.max_http_body_bytes)
        .map_err(CliError::classified)?;
    let collector = if export.is_some() {
        collector.with_body_chunk_limit(args.max_http_export_bytes)
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
    let (mut messages, mut issues) = (Vec::new(), Vec::new());
    let outcome = inspect(
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
            Event::BodyChunk {
                stream,
                generation,
                index,
                bytes,
                ..
            } => {
                if let Some(export) = &mut export {
                    export.chunk(stream, generation, index, &bytes)?;
                }
                Ok(())
            }
            Event::Message(message) => {
                let entity = export
                    .as_mut()
                    .map(|export| export.message(&message))
                    .transpose()?
                    .flatten();
                let mut message =
                    wire::Message::try_from(*message).map_err(CliError::classified)?;
                message.entity = entity;
                output.emit(message, &mut messages, rendering::render_message)
            }
            Event::Issue(issue) => output.emit(
                wire::Issue::from(issue),
                &mut issues,
                rendering::render_issue,
            ),
        },
    )?;
    if let Some(export) = export {
        export.finish()?;
    }
    let complete = wire::Complete::try_from((&outcome.run, outcome.summary, outcome.scopes))
        .map_err(CliError::classified)?;
    match format {
        ToolFormat::Json => emit_aggregate(
            Command::Http,
            wire::Report::from((messages, issues, complete)),
            Vec::new(),
        ),
        ToolFormat::Ndjson => stream.complete(complete, Vec::new()).map_err(Into::into),
        ToolFormat::Text => rendering::render_complete(&complete),
    }
}
