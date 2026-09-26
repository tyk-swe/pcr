// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::application_output::EventOutput;
use crate::output::{
    self,
    contract::{Command, ToolFormat},
    dns_analysis as wire,
};
use crate::{
    command_options::{DecodeArgs, OfflineLimitsArgs},
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_plain_line},
};
use packetcraftr_core::{
    analysis::{
        self,
        dns::{Collector, Event},
    },
    error::Kind,
};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// Keep one whole conversation: tcp:INDEX or udp:INDEX.
    #[arg(long)]
    pub(crate) stream: Option<String>,
    /// Additional DNS service ports; repeat to add services. Port 53 is always analyzed.
    #[arg(long = "dns-port")]
    pub(crate) dns_ports: Vec<u16>,
    #[command(flatten)]
    pub(crate) application: crate::command_options::ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

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
    let mut ports = args.dns_ports;
    ports.push(53);
    let collector = Collector::new(args.application.core(), ports).map_err(CliError::classified)?;
    let selector = args
        .stream
        .as_deref()
        .map(super::offline_analysis::parse_stream_selector)
        .transpose()?;
    let filter = selector.map(|selected| {
        format!(
            "{}.stream == {}",
            match selected.transport {
                analysis::StreamTransport::Tcp => "tcp",
                analysis::StreamTransport::Udp => "udp",
            },
            selected.index
        )
    });
    let setup = super::offline_analysis::prepare(args.limits, filter.as_deref(), &args.decode)?;
    // The session narrows the plan and raises the TCP/source-tracking flags
    // from the collector's declared needs.
    let session =
        analysis::Session::new(setup.registry.clone(), setup.options(), collector, selector);
    let mut reader = crate::input::open_capture(&args.path, args.limits.capture.reader)?;
    let (mut messages, mut transactions, mut issues) = (Vec::new(), Vec::new(), Vec::new());
    let mut output = EventOutput::new(
        format,
        stream,
        args.application.max_application_output_bytes,
    );
    let mut emit = |event: Event| -> Result<(), CliError> {
        match event {
            Event::Message(value) => output.emit(
                wire::Message::try_from(*value).map_err(CliError::classified)?,
                &mut messages,
                render_message,
            ),
            Event::Transaction(value) => output.emit(
                wire::Transaction::try_from(value).map_err(CliError::classified)?,
                &mut transactions,
                render_transaction,
            ),
            Event::Issue(value) => output.emit(wire::Issue(value), &mut issues, render_issue),
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
            Command::DnsRead,
            wire::Report {
                messages,
                transactions,
                issues,
                complete,
            },
            Vec::new(),
        ),
        ToolFormat::Ndjson => stream.complete(complete, Vec::new()).map_err(Into::into),
        ToolFormat::Text => write_plain_line(format_args!(
            "{} DNS messages; {} matched and {} unanswered transactions in {} captured frames",
            complete.summary.messages,
            complete.summary.matched_transactions,
            complete.summary.unanswered_transactions,
            complete.frames_read
        )),
    }
}
fn render_message(value: &wire::Message) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "DNS {:?}:{} message={} {:?} {}:{} -> {}:{} frames={:?} {}",
        value.transport,
        value.stream,
        value.index,
        value.status,
        value.flow.flow.source,
        value.flow.flow.source_port,
        value.flow.flow.destination,
        value.flow.flow.destination_port,
        value
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>(),
        value
            .fields
            .as_ref()
            .and_then(|fields| fields.get("questions"))
            .map(ToString::to_string)
            .unwrap_or_default()
    ))
}
fn render_transaction(value: &wire::Transaction) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "  transaction id={} {:?} queries={:?} response={:?} latest_latency={:?}",
        value.dns_id, value.status, value.queries, value.response, value.latest_query_latency
    ))
}
fn render_issue(value: &wire::Issue) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "  TCP stream={} frame={} {:?}",
        value.0.stream, value.0.number, value.0.status
    ))
}
