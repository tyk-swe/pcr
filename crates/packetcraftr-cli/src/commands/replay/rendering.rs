// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::Write;
use std::time::Duration;

use packetcraftr::{
    analysis::pcap::{self as capture, Format, Limits, Reader, Writer},
    netio as net, output,
};

use crate::capture_output::CaptureOutput;
use crate::errors::CliError;
use crate::rendering::{emit_stream_record, spaced_hex, write_stdout_line};

pub(super) fn replay_output_frame(
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<output::replay::Frame, packetcraftr::replay::Error> {
    let sequence = evidence.source_sequence;
    output::replay::Frame::try_from_evidence(evidence)
        .map_err(|source| packetcraftr::replay::Error::output(sequence, source.to_string()))
}

pub(super) fn write_replay_text_evidence(
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let result = replay_output_frame(evidence)?;
    write_stdout_line(format_args!(
        "{}: sent {} bytes via {} (index {}, {:?}) dlt={} {}",
        result.source_sequence,
        result.bytes_sent,
        result.interface.name,
        result.interface.index,
        result.link_mode,
        result.frame.link_type,
        spaced_hex(result.frame.bytes())
    ))
    .map_err(|source| packetcraftr::replay::Error::output(result.source_sequence, source.message))
}

pub(super) fn emit_replay_ndjson_evidence(
    sequence: &mut u64,
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let source_sequence = evidence.source_sequence;
    let result = replay_output_frame(evidence)?;
    emit_stream_record(output::contract::Command::Replay, sequence, result)
        .map_err(|source| packetcraftr::replay::Error::output(source_sequence, source.message))
}

pub(super) fn replay_capture_output<W: Write>(
    reader: &Reader<File>,
    output: W,
    format: Format,
    limits: packetcraftr::replay::Limits,
    max_interfaces: usize,
) -> Result<CaptureOutput<W>, CliError> {
    let writer = match format {
        Format::Pcap => {
            if reader.format() != Format::Pcap {
                return Err(CliError::classified(
                    capture::Error::MetadataNotRepresentable {
                        format,
                        field: "pcapng replay evidence",
                    },
                ));
            }
            let interface = reader.interfaces()[0].clone();
            let snap_length = usize::try_from(interface.snap_len).map_err(|_| {
                CliError::new(2, "capture snap length exceeds the platform size limit")
            })?;
            Writer::pcap_with_options(
                output,
                interface.link_type,
                capture::PcapOptions {
                    endianness: reader.endianness(),
                    timestamp_resolution: interface.timestamp_resolution,
                    snap_len: snap_length,
                    max_size: limits.max_frame_bytes,
                },
            )
        }
        Format::PcapNg => Writer::pcapng_with_options(
            output,
            capture::PcapNgOptions {
                endianness: reader.endianness(),
                max_size: limits.max_frame_bytes,
                max_interfaces,
            },
        ),
    }
    .map_err(CliError::classified)?;
    let mut output = CaptureOutput::interface_mapped(writer);
    output
        .set_stream_limits(Limits {
            max_frames: limits.max_frames,
            max_bytes: limits.max_bytes,
        })
        .map_err(CliError::classified)?;
    Ok(output)
}

pub(super) fn write_replay_capture_evidence<W: Write>(
    writer: &mut CaptureOutput<W>,
    evidence: packetcraftr::replay::FrameEvidence,
) -> Result<(), packetcraftr::replay::Error> {
    let sequence = evidence.source_sequence;
    writer
        .write_source_frame(
            evidence.source_interface_id,
            evidence.capture_interface,
            evidence.frame,
        )
        .map_err(|source| packetcraftr::replay::Error::output(sequence, source.to_string()))
}

pub(super) fn replay_stats(
    summary: &packetcraftr::replay::Summary,
    elapsed: Duration,
) -> output::envelope::Stats {
    output::envelope::Stats {
        packets_attempted: summary.frames_attempted,
        packets_completed: summary.frames_completed,
        bytes: summary.bytes_completed,
        elapsed,
        capture: net::capture::Statistics::default().into(),
    }
}
