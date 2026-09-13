// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::application_output::EventOutput;
use crate::{
    command_options::{ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs},
    errors::CliError,
    rendering::{StreamEncoder, emit_aggregate, write_plain_line},
};
use packetcraftr_cli::output::{
    self,
    contract::{Command, Format},
    http as wire,
};
use packetcraftr_core::{
    analysis::{
        self,
        http::{Collector, Event},
    },
    error::Kind,
};
use std::path::PathBuf;
#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// Select a whole TCP conversation, using tcp:INDEX.
    #[arg(long)]
    pub(crate) stream: Option<String>,
    /// Cleartext HTTP/1 ports; repeat to add services. Defaults: 80 and 8080.
    #[arg(long="http-port",default_values=["80","8080"])]
    pub(crate) http_ports: Vec<u16>,
    /// Maximum counted entity bytes in one message. Bodies are discarded.
    #[arg(long,default_value_t=16*1024*1024)]
    pub(crate) max_http_body_bytes: u64,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
pub(crate) fn run(args: Args, format: Format, stream: &StreamEncoder) -> Result<(), CliError> {
    args.application.validate_output()?;
    let mut ports = args.http_ports;
    ports.extend([80, 8080]);
    let mut collector = Collector::new(args.application.core(), ports, args.max_http_body_bytes)
        .map_err(CliError::classified)?;
    let selector = args
        .stream
        .as_deref()
        .map(super::offline_analysis::parse_stream_selector)
        .transpose()?;
    if selector.is_some_and(|selected| selected.transport != analysis::StreamTransport::Tcp) {
        return Err(CliError::new(
            Kind::Cli,
            "HTTP/1 inspection requires --stream tcp:INDEX",
        ));
    }
    let filter = selector.map(|selected| format!("tcp.stream == {}", selected.index));
    let setup = super::offline_analysis::prepare(args.limits, filter.as_deref(), &args.decode)?;
    let mut options = setup.options(true);
    options.track_sources = true;
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
                render_message,
            ),
            Event::Issue(issue) => output.emit(wire::Issue(issue), &mut issues, render_issue),
        }
    };
    let run = analysis::run_with_ip_events(
        &mut reader,
        setup.registry.clone(),
        &options,
        super::offline_analysis::ip_event_sink((format == Format::Ndjson).then(|| stream.clone())),
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
        Format::Json => emit_aggregate(
            Command::Http,
            wire::Report {
                messages,
                issues,
                complete,
            },
            Vec::new(),
        ),
        Format::Ndjson => stream.complete(complete, Vec::new()).map_err(Into::into),
        Format::Text => write_plain_line(format_args!(
            "{} HTTP/1 messages, {} complete, {} incomplete, {} malformed; {} requests without a captured final response",
            complete.summary.messages,
            complete.summary.complete_messages,
            complete.summary.incomplete_messages,
            complete.summary.malformed_messages,
            complete.summary.requests_without_final_response
        )),
        _ => unreachable!("format validated"),
    }
}
fn render_message(value: &wire::Message) -> Result<(), CliError> {
    let start = match &value.start {
        Some(wire::StartLine::Request { method, target, .. }) => {
            format!("{method} {}", escaped(target))
        }
        Some(wire::StartLine::Response { status, reason, .. }) => {
            format!("{status} {}", escaped(reason))
        }
        None => "partial headers".to_owned(),
    };
    write_plain_line(format_args!(
        "HTTP tcp:{} message={} {:?} {} body_bytes={} request={:?} frames={:?}",
        value.stream,
        value.index,
        value.status,
        start,
        value.body_bytes,
        value.request,
        value
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>()
    ))?;
    for header in &value.headers {
        write_plain_line(format_args!(
            "  {}: {}",
            header.name,
            escaped(&header.value)
        ))?;
    }
    if let Some(error) = &value.error {
        write_plain_line(format_args!("  {error}"))?;
    }
    Ok(())
}
fn render_issue(value: &wire::Issue) -> Result<(), CliError> {
    write_plain_line(format_args!(
        "  TCP stream={} frame={} {:?}",
        value.0.stream, value.0.number, value.0.status
    ))
}
fn escaped(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
