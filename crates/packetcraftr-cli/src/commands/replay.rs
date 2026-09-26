// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Replay CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;
mod selection;
#[cfg(test)]
mod tests;

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core as core;
use packetcraftr_core::budget::{Cancelled, Interrupted};
use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::{Format, Limits, Reader, Writer};
use packetcraftr_core::error::Kind;
use packetcraftr_netio as net;

use self::arguments::Args;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::FrameSelector;
use crate::input::{open_capture_file, validate_capture_stream_limits};
use crate::output::{self, contract::ExchangeFormat, stream::EncodeError};
use crate::rendering::{
    HumanWriteError, SourceCaptureWriter, StreamEncoder, emit_aggregate_with_stats,
    finish_compressed_output, stream_capture_error, write_stdout_line_with_interrupt,
};
use crate::system::InterfaceSelector;
use conversion::timing;

/// One validated replay: the source reader, the transmit providers, and the
/// bounds the run is held to.
struct ReplayRun {
    reader: Reader<std::fs::File>,
    options: packetcraftr::replay::Options,
    authorizer: packetcraftr::replay::SystemAuthorizer,
    transmitter: packetcraftr::replay::SystemTransmitter,
    clock: packetcraftr::clock::CancellableClock,
    selector: selection::Selector,
    requested_interface: Option<net::interface::Id>,
}

impl super::Spec for Args {
    type Format = crate::output::contract::ExchangeFormat;
    const CANCELLATION: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_millis(self.max_duration_ms))
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_duration_ms: Milliseconds @ Operation]);
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
    arguments.compression.validate(format.as_format())?;
    let mut prepared = prepare(&arguments)?;
    let filtered = prepared.selector.filter.is_some();
    let requested_interface = prepared.requested_interface.clone();
    let run = Run {
        reader: &mut prepared.reader,
        options: &prepared.options,
        selector: Some(&mut prepared.selector),
        authorizer: &mut prepared.authorizer,
        transmitter: &mut prepared.transmitter,
        clock: &mut prepared.clock,
    };
    match format {
        ExchangeFormat::Text => replay_text(run, filtered),
        ExchangeFormat::Json => replay_aggregate(run, requested_interface),
        ExchangeFormat::Ndjson => replay_stream(run, stream),
        ExchangeFormat::Pcap => replay_capture(
            run,
            CaptureSettings {
                format: capture::Format::Pcap,
                compression: arguments.compression,
            },
        ),
        ExchangeFormat::PcapNg => replay_capture(
            run,
            CaptureSettings {
                format: capture::Format::PcapNg,
                compression: arguments.compression,
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
    let filter = FrameSelector::compile_optional(
        arguments.filter.as_deref(),
        &registry,
        arguments.reader.max_frame_bytes,
    )?;
    if arguments.interface_maps.len() + arguments.filter_maps.len() > 256 {
        return Err(CliError::new(
            core::error::Kind::Usage,
            "replay permits at most 256 interface rules",
        ));
    }
    let requested_interface = InterfaceSelector::parse_optional(arguments.interface.as_deref())?
        .map(InterfaceSelector::into_id);
    let mut rules = Vec::new();
    for mapping in &arguments.interface_maps {
        let (source, destination) = mapping.split_once('=').ok_or_else(|| {
            CliError::new(
                core::error::Kind::Usage,
                "--map-interface requires SOURCE_ID=OUTPUT_INTERFACE",
            )
        })?;
        let source = source.parse::<u32>().map_err(|_| {
            CliError::new(
                core::error::Kind::Usage,
                "source interface must be an unsigned capture-global ID",
            )
        })?;
        rules.push(selection::Rule {
            condition: selection::Match::Source(source),
            interface: InterfaceSelector::parse(destination)?.into_id(),
        });
    }
    for mapping in &arguments.filter_maps {
        let (expression, destination) = mapping.rsplit_once("=>").ok_or_else(|| {
            CliError::new(
                core::error::Kind::Usage,
                "--map-filter requires EXPR=>OUTPUT_INTERFACE",
            )
        })?;
        let condition = FrameSelector::compile_optional(
            Some(expression),
            &registry,
            arguments.reader.max_frame_bytes,
        )?
        .expect("explicit filter");
        rules.push(selection::Rule {
            condition: selection::Match::Filter(condition),
            interface: InterfaceSelector::parse(destination)?.into_id(),
        });
    }
    policy.validate().map_err(CliError::classified)?;
    let limits = packetcraftr::replay::Limits::from_policy(
        &policy,
        arguments.reader.max_frame_bytes,
        Duration::from_millis(arguments.max_duration_ms),
    );
    limits.validate().map_err(CliError::classified)?;
    let options = packetcraftr::replay::Options {
        interface: requested_interface.clone(),
        repeat: arguments.repeat,
        inter_pass_delay: Duration::from_millis(arguments.inter_pass_delay_ms),
        link_mode: arguments.link_mode.into(),
        timing,
        limits,
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
    Ok(ReplayRun {
        reader,
        options,
        authorizer: packetcraftr::replay::SystemAuthorizer::new(
            Arc::clone(&registry),
            policy,
            arguments.allow_permissive_live,
        ),
        transmitter: packetcraftr::replay::SystemTransmitter::new(),
        clock: packetcraftr::clock::CancellableClock(crate::cancellation::signal().clone()),
        selector: selection::Selector {
            filter,
            rules,
            fallback: requested_interface.is_some(),
        },
        requested_interface,
    })
}

type Selector<'a> = Option<&'a mut dyn packetcraftr::replay::Selector>;

struct CaptureSettings {
    compression: crate::command_options::Compression,
    format: Format,
}

/// One replay, borrowed for the length of one render: the source, the frame
/// selector, and the three providers a run drives.
struct Run<'a, R, A, T, C> {
    reader: &'a mut Reader<R>,
    options: &'a packetcraftr::replay::Options,
    selector: Selector<'a>,
    authorizer: &'a mut A,
    transmitter: &'a mut T,
    clock: &'a mut C,
}

impl<R, A, T, C> Run<'_, R, A, T, C>
where
    R: Read + std::io::Seek,
    A: packetcraftr::policy::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    fn drive(
        self,
        record: impl FnMut(
            packetcraftr::replay::FrameEvidence,
        ) -> Result<(), packetcraftr::replay::Error>,
    ) -> Result<packetcraftr::replay::Summary, CliError> {
        packetcraftr::replay::run_repeated_with_selector(
            self.reader,
            self.options,
            self.selector,
            self.authorizer,
            self.transmitter,
            self.clock,
            record,
        )
        .map_err(CliError::classified)
    }
}

fn replay_text<R, A, T, C>(run: Run<'_, R, A, T, C>, filtered: bool) -> Result<(), CliError>
where
    R: Read + std::io::Seek,
    A: packetcraftr::policy::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let summary = run.drive(text_record)?;
    rendering::render_summary(&summary, filtered)
}

fn replay_aggregate<R, A, T, C>(
    run: Run<'_, R, A, T, C>,
    requested_interface: Option<net::interface::Id>,
) -> Result<(), CliError>
where
    R: Read + std::io::Seek,
    A: packetcraftr::policy::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let started = Instant::now();
    let link_mode = run.options.link_mode;
    let mut frames = Vec::new();
    let summary = run.drive(|evidence| {
        frames.push(output_frame(evidence)?);
        Ok(())
    })?;
    let stats = stats(&summary, started.elapsed());
    let result =
        output::replay::Report::from_summary(summary, requested_interface, link_mode, frames);
    emit_aggregate_with_stats(output::contract::Command::Replay, result, Vec::new(), stats)
}

fn replay_stream<R, A, T, C>(
    run: Run<'_, R, A, T, C>,
    stream: &StreamEncoder,
) -> Result<(), CliError>
where
    R: Read + std::io::Seek,
    A: packetcraftr::policy::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let started = Instant::now();
    let interface = run.options.interface.clone();
    let link_mode = run.options.link_mode;
    let summary = run.drive(|evidence| render_stream_record(stream, evidence))?;
    let stats = stats(&summary, started.elapsed());
    let result = output::replay::Report::from_summary(summary, interface, link_mode, Vec::new());
    Ok(stream.complete_with_stats(result, Vec::new(), stats)?)
}

fn replay_capture<R, A, T, C>(
    run: Run<'_, R, A, T, C>,
    settings: CaptureSettings,
) -> Result<(), CliError>
where
    R: Read + std::io::Seek,
    A: packetcraftr::policy::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
{
    let stdout = io::stdout();
    replay_capture_to(run, settings, stdout.lock())
}

fn replay_capture_to<R, A, T, C, W>(
    run: Run<'_, R, A, T, C>,
    settings: CaptureSettings,
    destination: W,
) -> Result<(), CliError>
where
    R: Read + std::io::Seek,
    A: packetcraftr::policy::Authorizer,
    T: packetcraftr::replay::Transmitter,
    C: packetcraftr::clock::Clock,
    W: Write,
{
    // Rejected before the destination is wrapped, so no compressed container is written.
    if settings.format == Format::Pcap && run.reader.format() != Format::Pcap {
        return Err(CliError::classified(
            capture::Error::MetadataNotRepresentable {
                format: settings.format,
                field: "pcapng replay evidence",
            },
        ));
    }
    let mut destination = settings.compression.writer(destination)?;
    let result = (|| {
        let mut writer = capture_writer(
            run.reader,
            &mut destination,
            settings.format,
            run.options.limits,
        )?;
        run.drive(|evidence| render_capture_record(&mut writer, evidence))?;
        writer
            .flush()
            .map_err(|source| stream_capture_error("flush capture output failed", source))
    })();
    finish_compressed_output(result, destination)
}

fn output_error(source_index: u64, message: impl Into<String>) -> packetcraftr::replay::Error {
    packetcraftr::replay::Error::output_at_source_index(source_index, message)
}

/// An interrupt observed while emitting a record fails the replay as the engine
/// fails one it observes itself, rather than as an output-sink failure.
fn interrupted_error(source_index: u64, interrupted: Interrupted) -> packetcraftr::replay::Error {
    match interrupted {
        Interrupted::Exceeded(exceeded) => packetcraftr::replay::Error::DurationLimit {
            source_index,
            actual: exceeded.actual,
            limit: exceeded.limit,
        },
        Interrupted::Cancelled(cancelled) => cancelled.into(),
        _ => Cancelled.into(),
    }
}

fn output_frame(
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<output::replay::Frame, packetcraftr::replay::Error> {
    let source_index = evidence.source_index;
    output::replay::Frame::try_from_evidence(evidence)
        .map_err(|source| output_error(source_index, source.to_string()))
}

fn text_record(
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    text_record_with(evidence, write_stdout_line_with_interrupt)
}

fn text_record_with(
    evidence: packetcraftr::replay::FrameEvidence,
    write_line: impl FnOnce(std::fmt::Arguments<'_>) -> Result<(), HumanWriteError>,
) -> Result<(), packetcraftr::replay::Error> {
    let result = output_frame(evidence)?;
    write_line(format_args!("{}", rendering::frame_line(&result))).map_err(|source| match source {
        HumanWriteError::Interrupted(interrupted) => {
            interrupted_error(result.source_index, interrupted)
        }
        HumanWriteError::Write(source) => output_error(
            result.source_index,
            format!("write stdout failed: {source}"),
        ),
    })
}

fn render_stream_record(
    stream: &StreamEncoder,
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let source_index = evidence.source_index;
    let result = output_frame(evidence)?;
    stream
        .emit_data(result, Vec::new())
        .map_err(|error| match error {
            EncodeError::Cancelled(cancelled) => interrupted_error(source_index, cancelled.into()),
            EncodeError::Deadline { source, .. } => interrupted_error(source_index, source.into()),
            error => output_error(source_index, error.to_string()),
        })
}

fn capture_writer<R: Read + std::io::Seek, W: Write>(
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

fn classic_writer<R: Read + std::io::Seek, W: Write>(
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
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let source_index = evidence.source_index;
    writer
        .write_source_frame(
            evidence.source_interface_id,
            evidence.capture_interface,
            evidence.frame,
        )
        .map_err(|source| output_error(source_index, source.to_string()))
}

fn stats(summary: &packetcraftr::replay::Summary, elapsed: Duration) -> packetcraftr::Stats {
    packetcraftr::Stats {
        packets_attempted: summary.frames_read,
        packets_completed: summary.frames_transmitted,
        bytes: summary.bytes_transmitted,
        elapsed,
        capture: net::capture::Statistics::default(),
    }
}
