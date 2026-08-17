// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use packetcraftr::{
    analysis::pcap::{self as capture, Format, Limits, Reader, Writer},
    netio as net, output,
};

use super::execution;
use crate::errors::CliError;
use crate::rendering::{
    CaptureWriter, capture_file_format, emit_aggregate_with_stats, emit_next, emit_with_stats,
    spaced_hex, write_stdout_line,
};

type Selector<'a> = Option<&'a mut dyn packetcraftr::replay::Selector>;

pub(super) struct CaptureSettings {
    pub(super) format: output::contract::Format,
    pub(super) max_interfaces: usize,
}

pub(super) fn render_text(
    reader: &mut Reader<File>,
    options: &packetcraftr::replay::Options,
    selector: Selector<'_>,
    authorizer: &mut packetcraftr::replay::SystemAuthorizer,
    transmitter: &mut packetcraftr::replay::SystemTransmitter,
    clock: &mut packetcraftr::clock::SystemClock,
    filtered: bool,
) -> Result<(), CliError> {
    let summary = execution::run(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        render_record,
    )?;
    if filtered {
        write_stdout_line(format_args!(
            "replayed {} of {} frame(s), {} byte(s), scheduled delay {:?}",
            summary.frames_transmitted,
            summary.frames_read,
            summary.bytes_transmitted,
            summary.scheduled_duration
        ))
    } else {
        write_stdout_line(format_args!(
            "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
            summary.frames_transmitted, summary.bytes_transmitted, summary.scheduled_duration
        ))
    }
}

pub(super) fn render_aggregate(
    reader: &mut Reader<File>,
    options: &packetcraftr::replay::Options,
    selector: Selector<'_>,
    authorizer: &mut packetcraftr::replay::SystemAuthorizer,
    transmitter: &mut packetcraftr::replay::SystemTransmitter,
    clock: &mut packetcraftr::clock::SystemClock,
    requested_interface: net::interface::Id,
) -> Result<(), CliError> {
    let started = Instant::now();
    let mut frames = Vec::new();
    let summary = execution::run(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        |evidence| {
            frames.push(output_frame(evidence)?);
            Ok(())
        },
    )?;
    let stats = stats(&summary, started.elapsed());
    let result = output::replay::Result::from_summary(
        summary,
        requested_interface,
        options.link_mode,
        frames,
    );
    emit_aggregate_with_stats(output::contract::Command::Replay, result, Vec::new(), stats)
}

pub(super) fn render_stream(
    reader: &mut Reader<File>,
    options: &packetcraftr::replay::Options,
    selector: Selector<'_>,
    authorizer: &mut packetcraftr::replay::SystemAuthorizer,
    transmitter: &mut packetcraftr::replay::SystemTransmitter,
    clock: &mut packetcraftr::clock::SystemClock,
    requested_interface: net::interface::Id,
) -> Result<(), CliError> {
    let started = Instant::now();
    let mut sequence = 0_u64;
    let summary = execution::run(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        |evidence| render_stream_record(&mut sequence, evidence),
    )?;
    let stats = stats(&summary, started.elapsed());
    let result = output::replay::Result::from_summary(
        summary,
        requested_interface,
        options.link_mode,
        Vec::new(),
    );
    emit_with_stats(
        output::contract::Command::Replay,
        sequence,
        result,
        Vec::new(),
        stats,
    )
}

pub(super) fn render_capture(
    reader: &mut Reader<File>,
    options: &packetcraftr::replay::Options,
    selector: Selector<'_>,
    authorizer: &mut packetcraftr::replay::SystemAuthorizer,
    transmitter: &mut packetcraftr::replay::SystemTransmitter,
    clock: &mut packetcraftr::clock::SystemClock,
    settings: CaptureSettings,
) -> Result<(), CliError> {
    let format = capture_file_format(settings.format)?;
    let stdout = io::stdout();
    let mut writer = capture_writer(
        reader,
        stdout.lock(),
        format,
        options.limits,
        settings.max_interfaces,
    )?;
    execution::run(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        |evidence| render_capture_record(&mut writer, evidence),
    )?;
    writer.flush().map_err(CliError::classified)
}

fn output_frame(
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<output::replay::Frame, packetcraftr::replay::Error> {
    let sequence = evidence.source_index;
    output::replay::Frame::try_from_evidence(evidence)
        .map_err(|source| packetcraftr::replay::Error::output(sequence, source.to_string()))
}

fn render_record(
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let result = output_frame(evidence)?;
    write_stdout_line(format_args!(
        "{}: sent {} bytes via {} (index {}, {:?}) dlt={} {}",
        result.source_index,
        result.bytes_sent,
        result.interface.name,
        result.interface.index,
        result.link_mode,
        result.frame.link_type,
        spaced_hex(result.frame.bytes())
    ))
    .map_err(|source| packetcraftr::replay::Error::output(result.source_index, source.message))
}

fn render_stream_record(
    sequence: &mut u64,
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let source_index = evidence.source_index;
    let result = output_frame(evidence)?;
    emit_next(output::contract::Command::Replay, sequence, result)
        .map_err(|source| packetcraftr::replay::Error::output(source_index, source.message))
}

fn capture_writer<W: Write>(
    reader: &Reader<File>,
    destination: W,
    format: Format,
    limits: packetcraftr::replay::Limits,
    max_interfaces: usize,
) -> Result<CaptureWriter<W>, CliError> {
    let writer = match format {
        Format::Pcap => classic_writer(reader, destination, format, limits)?,
        Format::PcapNg => Writer::pcapng_with_options(
            destination,
            capture::PcapNgOptions {
                endianness: reader.endianness(),
                max_size: limits.max_frame_bytes,
                max_interfaces,
            },
        )
        .map_err(CliError::classified)?,
    };
    let mut writer = CaptureWriter::for_source_interfaces(writer);
    writer
        .set_stream_limits(Limits {
            max_frames: limits.max_frames,
            max_bytes: limits.max_bytes,
        })
        .map_err(CliError::classified)?;
    Ok(writer)
}

fn classic_writer<W: Write>(
    reader: &Reader<File>,
    destination: W,
    format: Format,
    limits: packetcraftr::replay::Limits,
) -> Result<Writer<W>, CliError> {
    if reader.format() != Format::Pcap {
        return Err(CliError::classified(
            capture::Error::MetadataNotRepresentable {
                format,
                field: "pcapng replay evidence",
            },
        ));
    }
    let interface = reader.interfaces()[0].clone();
    let snap_length = usize::try_from(interface.snap_len)
        .map_err(|_| CliError::new(2, "capture snap length exceeds the platform size limit"))?;
    Writer::pcap_with_options(
        destination,
        interface.link_type,
        capture::PcapOptions {
            endianness: reader.endianness(),
            timestamp_resolution: interface.timestamp_resolution,
            snap_len: snap_length,
            max_size: limits.max_frame_bytes,
        },
    )
    .map_err(CliError::classified)
}

fn render_capture_record<W: Write>(
    writer: &mut CaptureWriter<W>,
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let sequence = evidence.source_index;
    writer
        .write_source_frame(
            evidence.source_interface_id,
            evidence.capture_interface,
            evidence.frame,
        )
        .map_err(|source| packetcraftr::replay::Error::output(sequence, source.to_string()))
}

fn stats(summary: &packetcraftr::replay::Summary, elapsed: Duration) -> output::envelope::Stats {
    output::envelope::Stats {
        packets_attempted: summary.frames_read,
        packets_completed: summary.frames_transmitted,
        bytes: summary.bytes_transmitted,
        elapsed,
        capture: net::capture::Statistics::default().into(),
    }
}
