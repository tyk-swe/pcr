// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::application_output::EventOutput;
use crate::{
    command_options::{DecodeArgs, OfflineLimitsArgs},
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_plain_line},
};
use packetcraftr_cli::output::{
    self,
    contract::{Command, ToolFormat},
    dns_analysis as wire,
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
    /// DNS service ports; repeat for nonstandard services (default: 53).
    #[arg(long = "dns-port", default_value = "53")]
    pub(crate) dns_ports: Vec<u16>,
    #[command(flatten)]
    pub(crate) application: crate::command_options::ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
pub(crate) fn run(args: Args, format: ToolFormat, stream: &StreamEncoder) -> Result<(), CliError> {
    args.application.validate_output()?;
    let mut collector =
        Collector::new(args.application.core(), args.dns_ports).map_err(CliError::classified)?;
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
    let mut reader = crate::input::open_capture(&args.path, args.limits.capture.reader)?;
    let mut options = setup.options(true);
    options.track_sources = true;
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
    let run = analysis::run_with_ip_events(
        &mut reader,
        setup.registry.clone(),
        &options,
        super::offline_analysis::ip_event_sink(
            (format == ToolFormat::Ndjson).then(|| stream.clone()),
        ),
        |record| {
            for event in collector
                .observe(&record)
                .map_err(packetcraftr_core::error::BoundaryError::from_error)?
            {
                emit(event).map_err(CliError::into_boundary_error)?;
            }
            Ok(())
        },
    )
    .map_err(CliError::classified)?;
    let scopes = collector.scopes().cloned().collect();
    let (trailing, summary) = collector.finish(&run).map_err(CliError::classified)?;
    for event in trailing {
        emit(event)?;
    }
    if selector.is_some() && run.frames_matched == 0 {
        return Err(CliError::new(Kind::Cli, "selected stream is not present"));
    }
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
