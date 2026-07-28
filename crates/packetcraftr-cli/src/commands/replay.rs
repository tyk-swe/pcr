// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Capture replay command.

use std::fs::File;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr::{
    capture::{self, Format, Frame, Limits, Reader, ReaderOptions, Writer},
    net, output, workflow,
};

use super::super::arguments::{CliReplayTiming, ReplayArgs};
use super::super::capture_output::CaptureOutput;
use super::super::errors::CliError;
use super::super::filtering::{self, Capabilities, FrameSelector};
use super::super::input::validate_capture_stream_limits;
use super::super::rendering::{
    capture_file_format, emit_json, emit_json_compact, spaced_hex, write_stdout_line,
};
use super::super::runtime::{default_registry_arc, validate_interface_selector};

/// Bridges the CLI display filter onto the replay engine's selection seam.
///
/// A frame the filter rejects is skipped before the engine authorizes,
/// delays, or transmits it, and a frame the filter cannot dissect stops the
/// operation instead of being quietly replayed or dropped.
struct DisplayFilterSelector<'a> {
    selector: &'a FrameSelector,
}

impl workflow::replay::Selector for DisplayFilterSelector<'_> {
    fn select(&mut self, number: u64, frame: &Frame) -> Result<bool, workflow::BoundaryError> {
        self.selector
            .keep(number, frame)
            .map_err(CliError::into_boundary_error)
    }
}

fn replay_timing(arguments: &ReplayArgs) -> Result<workflow::replay::Timing, CliError> {
    let timing = if let Some(rate) = arguments.rate {
        if matches!(arguments.timing, CliReplayTiming::Immediate) {
            return Err(CliError::new(
                2,
                "--rate cannot be combined with --timing immediate",
            ));
        }
        workflow::replay::Timing::FixedRate(rate)
    } else if let Some(speed) = arguments.speed {
        if matches!(arguments.timing, CliReplayTiming::Immediate) {
            return Err(CliError::new(
                2,
                "--speed cannot be combined with --timing immediate",
            ));
        }
        workflow::replay::Timing::Scaled(1.0 / speed)
    } else {
        match arguments.timing {
            CliReplayTiming::Original => workflow::replay::Timing::Original,
            CliReplayTiming::Immediate => workflow::replay::Timing::Immediate,
        }
    };
    timing.validate().map_err(CliError::classified)
}

fn requested_replay_interface(selector: &str) -> Result<net::interface::Id, CliError> {
    let index = validate_interface_selector("replay", Some(selector))?.unwrap_or(0);
    Ok(net::interface::Id {
        name: selector.to_owned(),
        index,
    })
}

pub(crate) fn run_replay(
    arguments: ReplayArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    validate_capture_stream_limits(
        arguments.policy.max_packets,
        arguments.policy.max_bytes,
        arguments.max_frame_bytes,
        arguments.max_interfaces,
    )?;
    let timing = replay_timing(&arguments)?;
    let registry = default_registry_arc()?;
    // The filter compiles with the other argument validation, before the
    // capture is opened and long before any authorization or transmission.
    let frame_filter = match arguments.filter.as_deref() {
        Some(source) => {
            let filter = filtering::compile(source, &registry, Capabilities::frames_only())?;
            Some(FrameSelector::new(
                Arc::clone(&registry),
                filter,
                arguments.max_frame_bytes,
            ))
        }
        None => None,
    };
    let requested_interface = requested_replay_interface(&arguments.interface)?;
    let policy = arguments.policy.clone().into_policy();
    policy.validate().map_err(CliError::classified)?;
    let limits = workflow::replay::Limits {
        max_frames: policy.max_packets_per_operation,
        max_bytes: policy.max_bytes_per_operation,
        max_frame_bytes: arguments.max_frame_bytes,
        max_duration: Duration::from_millis(arguments.max_duration_ms),
    }
    .validate()
    .map_err(CliError::classified)?;
    let file = File::open(&arguments.path).map_err(|source| {
        CliError::new(
            5,
            format!("open {} failed: {source}", arguments.path.display()),
        )
    })?;
    let mut reader = Reader::with_options(
        file,
        ReaderOptions {
            max_size: arguments.max_frame_bytes,
            max_interfaces_per_section: arguments.max_interfaces,
            ..ReaderOptions::default()
        },
    )
    .map_err(CliError::classified)?;
    let mut authorizer =
        workflow::replay::SystemAuthorizer::new(policy, registry, arguments.allow_malformed_live);
    let options = workflow::replay::Options {
        interface: requested_interface.clone(),
        link_mode: arguments.link_mode.into(),
        timing,
        limits,
    };
    let mut adapter = frame_filter
        .as_ref()
        .map(|selector| DisplayFilterSelector { selector });
    let selector = adapter
        .as_mut()
        .map(|adapter| adapter as &mut dyn workflow::replay::Selector);
    let mut transmitter = workflow::replay::SystemTransmitter::new();
    let mut clock = workflow::clock::SystemClock;
    let started = Instant::now();

    match output {
        output::contract::Format::Text => {
            let summary = execute_replay(
                &mut reader,
                &options,
                selector,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                write_replay_text_evidence,
            )?;
            match &frame_filter {
                None => write_stdout_line(format_args!(
                    "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
                    summary.frames_completed, summary.bytes_completed, summary.scheduled_duration
                )),
                Some(_) => write_stdout_line(format_args!(
                    "replayed {} of {} frame(s), {} byte(s), scheduled delay {:?}",
                    summary.frames_completed,
                    summary.frames_attempted,
                    summary.bytes_completed,
                    summary.scheduled_duration
                )),
            }
        }
        output::contract::Format::Json => {
            let mut frames = Vec::new();
            let summary = execute_replay(
                &mut reader,
                &options,
                selector,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    frames.push(replay_output_frame(evidence)?);
                    Ok(())
                },
            )?;
            let stats = replay_stats(&summary, started.elapsed());
            let result = output::replay::Result::from_summary(
                summary,
                requested_interface,
                options.link_mode,
                frames,
            );
            emit_json(
                &output::envelope::Aggregate::success(
                    output::contract::Command::Replay,
                    result,
                    Vec::new(),
                )
                .with_stats(stats),
            )
        }
        output::contract::Format::Ndjson => {
            let summary = execute_replay(
                &mut reader,
                &options,
                selector,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                emit_replay_ndjson_evidence,
            )?;
            let sequence = summary.frames_completed;
            let stats = replay_stats(&summary, started.elapsed());
            let result = output::replay::Result::from_summary(
                summary,
                requested_interface,
                options.link_mode,
                Vec::new(),
            );
            emit_json_compact(
                &output::envelope::Stream::success(
                    output::contract::Command::Replay,
                    sequence,
                    result,
                    Vec::new(),
                )
                .with_stats(stats),
            )
            .map_err(|error| error.at_sequence(sequence))
        }
        output::contract::Format::Pcap | output::contract::Format::Pcapng => {
            let format = capture_file_format(output)?;
            let stdout = io::stdout();
            let mut writer = replay_capture_output(
                &reader,
                stdout.lock(),
                format,
                limits,
                arguments.max_interfaces,
            )?;
            execute_replay(
                &mut reader,
                &options,
                selector,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| write_replay_capture_evidence(&mut writer, evidence),
            )?;
            writer.flush().map_err(CliError::classified)
        }
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Replay,
                format: output,
            },
        )),
    }
}

fn execute_replay<F>(
    reader: &mut Reader<File>,
    options: &workflow::replay::Options,
    selector: Option<&mut dyn workflow::replay::Selector>,
    authorizer: &mut workflow::replay::SystemAuthorizer,
    transmitter: &mut workflow::replay::SystemTransmitter,
    clock: &mut workflow::clock::SystemClock,
    sink: F,
) -> Result<workflow::replay::Summary, CliError>
where
    F: FnMut(workflow::replay::FrameEvidence) -> Result<(), workflow::replay::Error>,
{
    workflow::replay::run_with_selector(
        reader,
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        sink,
    )
    .map_err(replay_cli_error)
}

fn replay_output_frame(
    evidence: workflow::replay::FrameEvidence,
) -> Result<output::replay::Frame, workflow::replay::Error> {
    let sequence = evidence.source_sequence;
    output::replay::Frame::try_from_evidence(evidence)
        .map_err(|source| workflow::replay::Error::output(sequence, source.to_string()))
}

fn write_replay_text_evidence(
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

fn emit_replay_ndjson_evidence(
    evidence: workflow::replay::FrameEvidence,
) -> Result<(), workflow::replay::Error> {
    let sequence = evidence.source_sequence;
    let result = replay_output_frame(evidence)?;
    emit_json_compact(&output::envelope::Stream::success(
        output::contract::Command::Replay,
        sequence,
        result,
        Vec::new(),
    ))
    .map_err(|source| workflow::replay::Error::output(sequence, source.message))
}

fn replay_capture_output<W: Write>(
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

pub(crate) fn write_replay_capture_evidence<W: Write>(
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

fn replay_stats(summary: &workflow::replay::Summary, elapsed: Duration) -> output::envelope::Stats {
    output::envelope::Stats {
        packets_attempted: summary.frames_attempted,
        packets_completed: summary.frames_completed,
        bytes: summary.bytes_completed,
        elapsed,
        capture: net::capture::Statistics::default().into(),
    }
}

pub(crate) fn replay_cli_error(error: workflow::replay::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use packetcraftr::{
        capture::{self, Frame, LinkType, Reader, Writer},
        net, workflow,
    };

    use super::write_replay_capture_evidence;
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
}
