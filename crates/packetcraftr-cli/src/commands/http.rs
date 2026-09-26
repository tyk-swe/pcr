// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use self::arguments::Args;
use super::application_output::EventOutput;
use crate::output::{
    self,
    contract::{Command, ToolFormat},
    http as wire,
};
use crate::{
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_plain_line},
};
use packetcraftr_core::{
    analysis::{
        self,
        http::{Collector, Event},
    },
    error::Kind,
};

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_millis(
            self.limits.max_duration_ms,
        ))
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

pub(crate) fn run(args: Args, format: ToolFormat, stream: &StreamEncoder) -> Result<(), CliError> {
    args.application.validate_output()?;
    let mut ports = args.http_ports;
    ports.extend([80, 8080]);
    let collector = Collector::new(args.application.core(), ports, args.max_http_body_bytes)
        .map_err(CliError::classified)?;
    let selector = args
        .stream
        .as_deref()
        .map(super::offline_analysis::parse_stream_selector)
        .transpose()?;
    if selector.is_some_and(|selected| selected.transport != analysis::StreamTransport::Tcp) {
        return Err(CliError::new(
            Kind::Usage,
            "HTTP/1 inspection requires --stream tcp:INDEX",
        ));
    }
    let filter = selector.map(|selected| format!("tcp.stream == {}", selected.index));
    let setup = super::offline_analysis::prepare(args.limits, filter.as_deref(), &args.decode)?;
    // The session narrows the plan and raises the TCP/source-tracking flags
    // from the collector's declared needs.
    let session =
        analysis::Session::new(setup.registry.clone(), setup.options(), collector, selector);
    let mut reader = crate::input::open_capture(&args.path, args.limits.capture.reader)?;
    let (mut messages, mut issues) = (Vec::new(), Vec::new());
    let mut output = EventOutput::new(
        format,
        stream,
        args.application.max_application_output_bytes,
    );
    let mut emit = |event: Event| -> Result<(), CliError> {
        match event {
            Event::Message(message) => output.emit(
                wire::Message::try_from(*message).map_err(CliError::classified)?,
                &mut messages,
                rendering::render_message,
            ),
            Event::Issue(issue) => {
                output.emit(wire::Issue(issue), &mut issues, rendering::render_issue)
            }
        }
    };
    let outcome = session
        .run(
            &mut reader,
            super::offline_analysis::ip_event_sink(format, stream),
            |event| emit(event).map_err(CliError::into_boundary_error),
        )
        .map_err(CliError::classified)?;
    if outcome.selected_absent() {
        return Err(CliError::new(Kind::Usage, "selected stream is not present"));
    }
    let run = outcome.run;
    let scopes = outcome.scopes;
    let summary = outcome.summary;
    let complete = wire::Complete {
        frames_read: run.frames_read,
        frames_matched: run.frames_matched,
        summary,
        scopes,
        incomplete_datagrams: run.incomplete_sources.len(),
        source_outcomes_omitted: run.source_outcomes_omitted,
        ip_reassembly: output::reassembly::Report::from_analysis(&run.ip_reassembly),
    };
    match format {
        ToolFormat::Json => emit_aggregate(
            Command::Http,
            wire::Report {
                messages,
                issues,
                complete,
            },
            Vec::new(),
        ),
        ToolFormat::Ndjson => stream.complete(complete, Vec::new()).map_err(Into::into),
        ToolFormat::Text => write_plain_line(format_args!(
            "{} HTTP/1 messages, {} complete, {} incomplete, {} malformed; {} requests without a captured final response",
            complete.summary.messages,
            complete.summary.complete_messages,
            complete.summary.incomplete_messages,
            complete.summary.malformed_messages,
            complete.summary.requests_without_final_response
        )),
    }
}
