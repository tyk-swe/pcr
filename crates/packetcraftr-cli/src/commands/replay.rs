// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Replay CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;
#[cfg(test)]
mod tests;

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use packetcraftr::Providers;
use packetcraftr::clock::Clock;
use packetcraftr::replay::{
    Event, FrameEvidence, Request, Source,
    routing::{self, Routing, Rule},
};
use packetcraftr::route;
use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::{Format, Limits, Reader, Writer, compression};
use packetcraftr_core::error::{BoundaryError, Kind};

use self::arguments::Args;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering;
use crate::input::{open_capture_file, validate_capture_stream_limits};
use crate::output::{self, contract::ExchangeFormat, stream::EncodeError};
use crate::rendering::{
    HumanWriteError, SourceCaptureWriter, StreamEncoder, emit_aggregate_with_stats,
    finish_compressed_output, stream_capture_error, write_stdout_line_with_interrupt,
};
use crate::system::InterfaceSelector;
use conversion::timing;

/// One validated replay: the client it runs on and its request over a
/// validated capture snapshot.
struct ReplayRun {
    client: crate::system::Client,
    request: Request<std::fs::File>,
    filtered: bool,
}

impl super::Spec for Args {
    type Format = crate::output::contract::ExchangeFormat;
    const CANCELLATION: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.duration.max_duration())
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.duration.resources(settings);
        self.reader.resources(settings);
        self.policy.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    arguments: Args,
    format: ExchangeFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let compression = arguments.compression.for_output(format.as_format())?;
    let ReplayRun {
        client,
        request,
        filtered,
    } = prepare(&arguments)?;
    match format {
        ExchangeFormat::Text => replay_text(&client, request, filtered),
        ExchangeFormat::Json => replay_aggregate(&client, request),
        ExchangeFormat::Ndjson => replay_stream(&client, request, stream),
        ExchangeFormat::Pcap => replay_capture(
            &client,
            request,
            CaptureSettings {
                format: capture::Format::Pcap,
                compression,
            },
        ),
        ExchangeFormat::PcapNg => replay_capture(
            &client,
            request,
            CaptureSettings {
                format: capture::Format::PcapNg,
                compression,
            },
        ),
    }
}

fn prepare(arguments: &Args) -> Result<ReplayRun, CliError> {
    let policy = arguments.policy.clone().into_policy();
    // Replay's aggregate ceilings come from the traffic policy rather than
    // from `--max-frames`/`--max-bytes`, but they bound the same capture
    // stream and are validated against the same cross-field rule.
    let capture_limits = OfflineCaptureLimitsArgs {
        max_frames: policy.max_packets_per_operation,
        max_bytes: policy.max_bytes_per_operation,
        reader: arguments.reader,
    };
    validate_capture_stream_limits(capture_limits)?;
    let timing = timing(arguments)?;
    let registry = packetcraftr_core::protocol::builtin::registry();
    let max_frame_bytes = arguments.reader.max_frame_bytes;
    let filter = filtering::optional_frame_selector(
        arguments.filter.as_deref(),
        &registry,
        max_frame_bytes,
    )?;
    let rule_count = arguments.interface_maps.len() + arguments.filter_maps.len();
    if rule_count > routing::MAX_RULES {
        return Err(routing::Error::TooMany { count: rule_count }.into());
    }
    let fallback = arguments
        .interface
        .as_ref()
        .map(crate::command_options::Selector::get)
        .transpose()?
        .map(route::Interface::from);
    let interface = |text: &str| InterfaceSelector::parse(text).map(route::Interface::from);
    let mut rules = Vec::with_capacity(rule_count);
    for mapping in &arguments.interface_maps {
        rules.push(Rule::parse_source(mapping, interface)?);
    }
    for mapping in &arguments.filter_maps {
        rules.push(Rule::parse_filter(
            mapping,
            |expression| filtering::frame_selector(expression, &registry, max_frame_bytes),
            interface,
        )?);
    }
    let routing = Routing::new(rules, fallback)?;
    policy.validate().map_err(CliError::classified)?;
    let limits = packetcraftr::replay::Limits::from_policy(
        &policy,
        arguments.reader.max_frame_bytes,
        arguments.duration.max_duration(),
    );
    limits.validate().map_err(CliError::classified)?;
    let options = packetcraftr::replay::Options {
        repeat: arguments.repeat,
        inter_pass_delay: Duration::from_millis(arguments.inter_pass_delay_ms),
        link_mode: arguments.link_mode.into(),
        timing,
        limits,
        allow_permissive_live: arguments.allow_permissive_live,
    };
    options.validate().map_err(CliError::classified)?;
    let mut input = open_capture_file(&arguments.path, arguments.reader)?;
    let reader = crate::input::snapshot_capture(
        &mut input,
        arguments.reader,
        capture::Limits {
            max_frames: limits.max_source_frames,
            max_bytes: arguments.reader.max_decoded_bytes,
        },
    )?;
    let filtered = filter.is_some();
    let mut request = Request::new(Source::seekable(reader), routing, options);
    request.filter = filter;
    Ok(ReplayRun {
        client: crate::system::client(registry, policy, crate::system::Runtime::Client),
        request,
        filtered,
    })
}

/// A refused interface rule, in its option's own words.
impl From<routing::Error> for CliError {
    fn from(error: routing::Error) -> Self {
        let message = match &error {
            routing::Error::SourceSyntax => {
                "--map-interface requires SOURCE_ID=OUTPUT_INTERFACE".into()
            }
            routing::Error::FilterSyntax => "--map-filter requires EXPR=>OUTPUT_INTERFACE".into(),
            routing::Error::SourceId { .. } => {
                "source interface must be an unsigned capture-global ID".into()
            }
            routing::Error::TooMany { .. } => {
                format!(
                    "replay permits at most {} interface rules",
                    routing::MAX_RULES
                )
            }
            _ => return Self::classified(error),
        };
        Self::refused_option(message, &error)
    }
}

/// The fallback interface as the caller named it, which the report publishes.
fn requested_interface<R>(request: &Request<R>) -> Option<route::Interface> {
    request.routing.fallback().cloned()
}

struct CaptureSettings {
    compression: crate::command_options::Compression,
    format: Format,
}

/// Runs `request` on `client`, publishing each confirmed frame to `sink`.
fn drive<P, K, R>(
    client: &packetcraftr::Client<P, K>,
    request: Request<R>,
    sink: impl packetcraftr::Sink<Event, Ack = ()>,
) -> Result<packetcraftr::replay::Report, CliError>
where
    P: Providers,
    K: Clock,
    R: Read,
{
    client.replay(request, sink).map_err(CliError::classified)
}

fn replay_text<P: Providers, K: Clock, R: Read>(
    client: &packetcraftr::Client<P, K>,
    request: Request<R>,
    filtered: bool,
) -> Result<(), CliError> {
    // The sink runs on a runtime worker, outside this thread's dispatch
    // scope, so it enters the invocation's deadline itself.
    let deadline = crate::invocation::deadline();
    let report = drive(client, request, move |Event::Frame(evidence): Event| {
        let _scope = crate::invocation::enter_deadline(deadline.clone());
        text_record_with(evidence, write_stdout_line_with_interrupt)
    })?;
    rendering::render_summary(&report, filtered)
}

fn replay_aggregate<P: Providers, K: Clock, R: Read>(
    client: &packetcraftr::Client<P, K>,
    request: Request<R>,
) -> Result<(), CliError> {
    let started = Instant::now();
    let requested_interface = requested_interface(&request);
    let link_mode = request.options.link_mode;
    // Each frame converts as it is published, so a frame the output cannot
    // represent stops the replay before the next one is sent.
    let frames = Arc::new(Mutex::new(Vec::new()));
    let collected = Arc::clone(&frames);
    let report = drive(client, request, move |Event::Frame(evidence): Event| {
        let frame = output_frame(evidence)?;
        collected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(frame);
        Ok(())
    })?;
    let frames = std::mem::take(&mut *frames.lock().unwrap_or_else(PoisonError::into_inner));
    let stats = output::envelope::Stats::from((&report, started.elapsed()));
    let result = output::replay::Report::try_from((report, requested_interface, link_mode, frames))
        .map_err(CliError::classified)?;
    emit_aggregate_with_stats(output::contract::Command::Replay, result, Vec::new(), stats)
}

fn replay_stream<P: Providers, K: Clock, R: Read>(
    client: &packetcraftr::Client<P, K>,
    request: Request<R>,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let started = Instant::now();
    let interface = requested_interface(&request);
    let link_mode = request.options.link_mode;
    let records = stream.clone();
    let report = drive(client, request, move |Event::Frame(evidence): Event| {
        render_stream_record(&records, evidence)
    })?;
    let stats = output::envelope::Stats::from((&report, started.elapsed()));
    let result = output::replay::Report::try_from((report, interface, link_mode, Vec::new()))
        .map_err(CliError::classified)?;
    Ok(stream.complete_with_stats(result, Vec::new(), stats)?)
}

fn replay_capture<P: Providers, K: Clock, R: Read>(
    client: &packetcraftr::Client<P, K>,
    request: Request<R>,
    settings: CaptureSettings,
) -> Result<(), CliError> {
    replay_capture_to(client, request, settings, io::stdout())
}

/// The capture output a replay's sink writes into from its worker, and the
/// command finalizes once the replay returns.
struct Shared<T>(Arc<Mutex<Option<T>>>);

impl<T> Shared<T> {
    fn new(value: T) -> Self {
        Self(Arc::new(Mutex::new(Some(value))))
    }

    fn take(&self) -> Option<T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<W: Write> Write for Shared<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut *self.0.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(writer) => writer.write(bytes),
            None => Err(io::Error::other(
                "replay capture output is already finished",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut *self.0.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(writer) => writer.flush(),
            None => Ok(()),
        }
    }
}

fn replay_capture_to<P, K, R, W>(
    client: &packetcraftr::Client<P, K>,
    request: Request<R>,
    settings: CaptureSettings,
    destination: W,
) -> Result<(), CliError>
where
    P: Providers,
    K: Clock,
    R: Read,
    W: Write + Send + 'static,
{
    // Rejected before the destination is wrapped, so no compressed container is written.
    if settings.format == Format::Pcap && request.source.reader().format() != Format::Pcap {
        return Err(CliError::classified(
            capture::Error::MetadataNotRepresentable {
                format: settings.format,
                field: "pcapng replay evidence",
            },
        ));
    }
    // The command keeps the compressor, so it is finished even when the
    // capture writer or the replay fails.
    let destination = Shared::new(settings.compression.writer(destination)?);
    let result = (|| {
        let writer = Shared::new(capture_writer(
            request.source.reader(),
            destination.clone(),
            settings.format,
            request.options.limits,
        )?);
        let records = writer.clone();
        let replayed =
            drive(
                client,
                request,
                move |Event::Frame(evidence): Event| match &mut *records
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                {
                    Some(writer) => render_capture_record(writer, evidence),
                    None => Err(output_failure(
                        "replay capture output is already finished",
                        io::Error::other("capture writer closed"),
                    )),
                },
            );
        let mut writer = writer.take();
        replayed?;
        writer
            .as_mut()
            .map_or(Ok(()), SourceCaptureWriter::flush)
            .map_err(|source| stream_capture_error("flush capture output failed", source))
    })();
    let destination: compression::Output<W> = destination
        .take()
        .expect("only the command finishes the capture output");
    finish_compressed_output(result, destination)
}

/// An output failure the replay reports at the frame it failed on: `message`
/// names what failed, and the error it carries is the first cause.
fn output_failure(
    message: &'static str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> BoundaryError {
    let classification = CliError::new(Kind::Io, message).classification;
    let causes = std::iter::once(source.to_string())
        .chain(packetcraftr_core::error::source_chain(&source))
        .collect();
    BoundaryError::with_source(message, classification, causes, source)
}

fn output_frame(evidence: FrameEvidence) -> Result<output::replay::Frame, BoundaryError> {
    output::replay::Frame::try_from(evidence)
        .map_err(|source| output_failure("replay frame output failed", source))
}

/// Writes one frame line. An interrupt observed while writing fails the
/// replay as an interruption, rather than as an output-sink failure.
fn text_record_with(
    evidence: FrameEvidence,
    write_line: impl FnOnce(std::fmt::Arguments<'_>) -> Result<(), HumanWriteError>,
) -> Result<(), BoundaryError> {
    let result = output_frame(evidence)?;
    write_line(format_args!("{}", rendering::frame_line(&result))).map_err(|source| match source {
        HumanWriteError::Interrupted(interrupted) => BoundaryError::from_error(interrupted),
        HumanWriteError::Write(source) => output_failure("write stdout failed", source),
    })
}

fn render_stream_record(
    stream: &StreamEncoder,
    evidence: FrameEvidence,
) -> Result<(), BoundaryError> {
    let result = output_frame(evidence)?;
    stream
        .emit_data(result, Vec::new())
        .map_err(|error| match error {
            EncodeError::Cancelled(cancelled) => BoundaryError::from_error(cancelled),
            EncodeError::Deadline { source, .. } => BoundaryError::from_error(source),
            error => output_failure("write replay record failed", error),
        })
}

fn capture_writer<R: Read, W: Write>(
    reader: &Reader<R>,
    destination: W,
    format: Format,
    limits: packetcraftr::replay::Limits,
) -> Result<SourceCaptureWriter<W>, CliError> {
    let writer = match format {
        Format::Pcap => classic_writer(reader, destination, limits)?,
        Format::PcapNg => Writer::pcapng_with_options(
            destination,
            capture::PcapNgOptions {
                endianness: reader.endianness(),
                max_size: limits.max_frame_bytes,
                // --max-interfaces bounds each input section, not the one output section.
                max_interfaces: capture::DEFAULT_TOTAL_INTERFACE_LIMIT,
                stream_limits: stream_limits(limits),
            },
        )
        .map_err(|source| stream_capture_error("initialize capture output failed", source))?,
    };
    Ok(SourceCaptureWriter::new(writer))
}

fn classic_writer<R: Read, W: Write>(
    reader: &Reader<R>,
    destination: W,
    limits: packetcraftr::replay::Limits,
) -> Result<Writer<W>, CliError> {
    // replay_capture_to admits only a classic pcap source, which always
    // exposes its single global interface
    let interface = reader.interfaces()[0].clone();
    let snap_length = usize::try_from(interface.snap_len).map_err(|_| {
        CliError::new(
            Kind::Usage,
            "capture snap length exceeds the platform size limit",
        )
    })?;
    Writer::pcap_with_options(
        destination,
        interface.link_type,
        capture::PcapOptions {
            endianness: reader.endianness(),
            timestamp_resolution: interface.timestamp_resolution,
            snap_len: snap_length,
            max_size: limits.max_frame_bytes,
            stream_limits: stream_limits(limits),
        },
    )
    .map_err(|source| stream_capture_error("initialize capture output failed", source))
}

const fn stream_limits(limits: packetcraftr::replay::Limits) -> Limits {
    Limits {
        max_frames: limits.max_source_frames,
        max_bytes: limits.max_transmitted_bytes,
    }
}

fn render_capture_record<W: Write>(
    writer: &mut SourceCaptureWriter<W>,
    evidence: FrameEvidence,
) -> Result<(), BoundaryError> {
    writer
        .write_source_frame(
            evidence.source_interface_id,
            evidence.capture_interface,
            evidence.frame,
        )
        .map_err(|source| output_failure("write capture output failed", source))
}
