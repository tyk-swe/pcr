// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use packetcraftr_core::analysis::http2::{Collector, Event};

use self::arguments::Args;
use super::offline_analysis::{Inspection, complete_application, inspect, require_tcp_stream};
use crate::errors::CliError;
use crate::output::{
    contract::{Command, Format},
    http2 as wire,
};
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
        crate::resources::declare!(
            settings, self,
            [
                max_http2_frames: Count @ Operation,
                max_http2_streams: Count @ Operation,
                max_http2_active_streams: Count @ ActiveState,
                max_http2_frame_bytes: Bytes @ ActiveState,
                max_http2_header_block_bytes: Bytes @ ActiveState,
                max_http2_header_bytes: Bytes @ ActiveState,
                max_http2_headers: Count @ ActiveState,
                max_http2_table_bytes: Bytes @ ActiveState,
                max_http2_continuations: Count @ ActiveState,
                max_http2_pending_settings: Count @ ActiveState,
                max_http2_body_bytes: Bytes @ Operation,
            ]
        );
        self.application.resources(settings);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(true),
        );
    }

    fn run(
        self,
        format: Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

fn run(args: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    args.application.validate_output()?;
    let mut ports = args.http2_ports.clone();
    ports.extend([80, 8080]);
    let mut collector = Collector::new(args.application.core(), ports, args.http2_limits())
        .map_err(CliError::classified)?;
    if let Some(deadline) = crate::invocation::deadline() {
        collector = collector.with_deadline(deadline);
    }
    let selector = require_tcp_stream(args.stream.as_ref(), "HTTP/2")?;
    let (mut frames, mut messages, mut issues, mut connections) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
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
            Event::Frame(frame) => output.emit(
                wire::Frame::try_from(*frame).map_err(CliError::classified)?,
                &mut frames,
                rendering::render_frame,
            ),
            Event::Message(message) => output.emit(
                wire::Message::try_from(*message).map_err(CliError::classified)?,
                &mut messages,
                |message| rendering::render_message(message, stream.presentation()),
            ),
            Event::Issue(issue) => output.emit(
                wire::Issue::try_from(issue).map_err(CliError::classified)?,
                &mut issues,
                rendering::render_issue,
            ),
            Event::Connection(connection) => output.emit(
                wire::Connection::try_from(*connection).map_err(CliError::classified)?,
                &mut connections,
                rendering::render_connection,
            ),
        },
    )?;
    let complete = wire::Complete::try_from((&outcome.run, outcome.summary, outcome.scopes))
        .map_err(CliError::classified)?;
    complete_application(
        Command::Http2,
        format,
        stream,
        complete,
        |complete| wire::Report::from((frames, messages, issues, connections, complete)),
        rendering::render_complete,
    )
}
