// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io::Write;
use std::time::Duration;

use packetcraftr::{
    capture::{self, Format, Limits, Reader, Writer},
    net, output, workflow,
};

use crate::capture_output::CaptureOutput;
use crate::errors::CliError;
use crate::rendering::{emit_json_compact, next_stream_sequence, spaced_hex, write_stdout_line};

pub(super) fn replay_output_frame(
    evidence: workflow::replay::FrameEvidence,
) -> Result<output::replay::Frame, workflow::replay::Error> {
    let sequence = evidence.source_sequence;
    output::replay::Frame::try_from_evidence(evidence)
        .map_err(|source| workflow::replay::Error::output(sequence, source.to_string()))
}

pub(super) fn write_replay_text_evidence(
    evidence: workflow::replay::FrameEvidence,
) -> Result<(), workflow::replay::Error> {
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
    .map_err(|source| workflow::replay::Error::output(result.source_sequence, source.message))
}

pub(super) fn emit_replay_ndjson_evidence(
    sequence: &mut u64,
    evidence: workflow::replay::FrameEvidence,
) -> Result<(), workflow::replay::Error> {
    let source_sequence = evidence.source_sequence;
    let result = replay_output_frame(evidence)?;
    emit_json_compact(&output::envelope::Stream::success(
        output::contract::Command::Replay,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|source| workflow::replay::Error::output(source_sequence, source.message))?;
    *sequence = next_stream_sequence(*sequence)
        .map_err(|source| workflow::replay::Error::output(source_sequence, source.message))?;
    Ok(())
}

pub(super) fn replay_capture_output<W: Write>(
    reader: &Reader<File>,
    output: W,
    format: Format,
    limits: workflow::replay::Limits,
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
            let interface = reader.interfaces()[0];
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
    let mut output = CaptureOutput::source_preserving(writer);
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
    evidence: workflow::replay::FrameEvidence,
) -> Result<(), workflow::replay::Error> {
    let sequence = evidence.source_sequence;
    writer
        .write_source_frame(
            evidence.source_interface_id,
            evidence.capture_interface,
            evidence.frame,
        )
        .map_err(|source| workflow::replay::Error::output(sequence, source.to_string()))
}

pub(super) fn replay_stats(
    summary: &workflow::replay::Summary,
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use packetcraftr::{
        capture::{self, Frame, LinkType, Reader, Writer},
        net, workflow,
    };

    use super::{emit_replay_ndjson_evidence, write_replay_capture_evidence};
    use crate::capture_output::CaptureOutput;

    #[test]
    fn replay_pcapng_evidence_preserves_source_timestamp_metadata() {
        let timestamp = SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_millis(500))
            .unwrap();
        let mut frame = Frame::new(timestamp, LinkType::RAW, vec![0x60; 40]).unwrap();
        frame.interface = Some(7);
        let evidence = workflow::replay::FrameEvidence {
            source_sequence: 0,
            source_interface_id: Some(7),
            capture_interface: capture::Interface {
                link_type: LinkType::RAW,
                snap_len: 128,
                timestamp_resolution: capture::TimestampResolution::Binary(10),
                timestamp_offset: -1,
            },
            interface: net::interface::Id {
                name: "test0".to_owned(),
                index: 1,
            },
            link_mode: net::link::Mode::Layer3,
            scheduled_delay: Duration::ZERO,
            bytes_sent: 40,
            frame: frame.clone(),
        };
        let writer = Writer::pcapng(Vec::new()).unwrap();
        let mut writer = CaptureOutput::source_preserving(writer);
        write_replay_capture_evidence(&mut writer, evidence).unwrap();

        let mut reader = Reader::new(std::io::Cursor::new(writer.into_inner())).unwrap();
        let decoded = reader.next_frame().unwrap().unwrap();
        frame.interface = Some(0);
        assert_eq!(decoded, frame);
        assert_eq!(
            reader.interfaces()[0],
            capture::Interface {
                link_type: LinkType::RAW,
                snap_len: 128,
                timestamp_resolution: capture::TimestampResolution::Binary(10),
                timestamp_offset: -1,
            }
        );
    }

    #[test]
    fn replay_output_keeps_source_position_separate_from_stream_position() {
        let frame = Frame::new(
            SystemTime::UNIX_EPOCH,
            capture::LinkType::RAW,
            vec![0x60; 40],
        )
        .unwrap();
        let evidence = workflow::replay::FrameEvidence {
            source_sequence: 17,
            source_interface_id: None,
            capture_interface: capture::Interface {
                link_type: capture::LinkType::RAW,
                snap_len: 128,
                timestamp_resolution: capture::TimestampResolution::Decimal(6),
                timestamp_offset: 0,
            },
            interface: net::interface::Id {
                name: "test0".to_owned(),
                index: 1,
            },
            link_mode: net::link::Mode::Layer3,
            scheduled_delay: Duration::ZERO,
            bytes_sent: 40,
            frame,
        };

        let later_evidence = workflow::replay::FrameEvidence {
            source_sequence: 42,
            ..evidence.clone()
        };
        let mut stream_sequence = 0;
        let ((first, second), rendered) = crate::rendering::capture_stdout(|| {
            (
                emit_replay_ndjson_evidence(&mut stream_sequence, evidence),
                emit_replay_ndjson_evidence(&mut stream_sequence, later_evidence),
            )
        });
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(stream_sequence, 2);

        let records = rendered
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["result"]["source_sequence"], 17);
        assert_eq!(records[1]["sequence"], 1);
        assert_eq!(records[1]["result"]["source_sequence"], 42);
    }
}
