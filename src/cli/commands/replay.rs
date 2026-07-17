// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Capture replay command.

use std::fs::File;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use packetcraftr::{
    capture::{self, Format, Limits, Reader, ReaderOptions, Writer},
    net, output, workflow,
};

use super::super::arguments::{CliReplayTiming, ReplayArgs};
use super::super::errors::CliError;
use super::super::rendering::{
    capture_file_format, emit_json, emit_json_compact, spaced_hex, write_stdout_line,
};
use super::super::runtime::{default_registry_arc, validate_interface_selector};
use super::offline::validate_capture_stream_limits;

#[derive(Clone, Copy, Debug)]
pub(in crate::cli) struct ReplayInterfaceMapping {
    source_id: Option<u32>,
    output_id: u32,
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

pub(in crate::cli) fn run_replay(
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
    let registry = default_registry_arc()?;
    let mut authorizer =
        workflow::replay::SystemAuthorizer::new(policy, registry, arguments.allow_malformed_live);
    let options = workflow::replay::Options {
        interface: requested_interface.clone(),
        link_mode: arguments.link_mode.into(),
        timing,
        limits,
    };
    let mut transmitter = workflow::replay::SystemTransmitter::new();
    let mut clock = workflow::clock::SystemClock;
    let started = Instant::now();

    match output {
        output::contract::Format::Text => {
            let summary = execute_replay(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                write_replay_text_evidence,
            )?;
            write_stdout_line(format_args!(
                "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
                summary.frames_completed, summary.bytes_completed, summary.scheduled_duration
            ))
        }
        output::contract::Format::Json => {
            let mut frames = Vec::new();
            let summary = execute_replay(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| collect_replay_evidence(&mut frames, evidence),
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
            let mut writer = replay_capture_writer(
                &reader,
                stdout.lock(),
                format,
                limits,
                arguments.max_interfaces,
            )?;
            let mut interfaces = Vec::<ReplayInterfaceMapping>::new();
            execute_replay(
                &mut reader,
                &options,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    write_replay_capture_evidence(&mut writer, format, &mut interfaces, evidence)
                },
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
    authorizer: &mut workflow::replay::SystemAuthorizer,
    transmitter: &mut workflow::replay::SystemTransmitter,
    clock: &mut workflow::clock::SystemClock,
    sink: F,
) -> Result<workflow::replay::Summary, CliError>
where
    F: FnMut(workflow::replay::FrameEvidence) -> Result<(), workflow::replay::Error>,
{
    workflow::replay::run(reader, options, authorizer, transmitter, clock, sink)
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

fn collect_replay_evidence(
    frames: &mut Vec<output::replay::Frame>,
    evidence: workflow::replay::FrameEvidence,
) -> Result<(), workflow::replay::Error> {
    frames.push(replay_output_frame(evidence)?);
    Ok(())
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

fn replay_capture_writer<W: Write>(
    reader: &Reader<File>,
    output: W,
    format: Format,
    limits: workflow::replay::Limits,
    max_interfaces: usize,
) -> Result<Writer<W>, CliError> {
    let mut writer = match format {
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
    writer
        .set_stream_limits(Limits {
            max_frames: limits.max_frames,
            max_bytes: limits.max_bytes,
        })
        .map_err(CliError::classified)?;
    Ok(writer)
}

pub(in crate::cli) fn write_replay_capture_evidence<W: Write>(
    writer: &mut Writer<W>,
    format: Format,
    interfaces: &mut Vec<ReplayInterfaceMapping>,
    evidence: workflow::replay::FrameEvidence,
) -> Result<(), workflow::replay::Error> {
    let sequence = evidence.source_sequence;
    let mut frame = evidence.frame;
    frame.interface = match format {
        Format::Pcap => None,
        Format::PcapNg => {
            let interface = match interfaces
                .iter()
                .find(|mapping| mapping.source_id == evidence.source_interface_id)
            {
                Some(mapping) => mapping.output_id,
                None => {
                    let interface = writer
                        .add_interface_description(evidence.capture_interface)
                        .map_err(|source| {
                            workflow::replay::Error::output(sequence, source.to_string())
                        })?;
                    interfaces.push(ReplayInterfaceMapping {
                        source_id: evidence.source_interface_id,
                        output_id: interface,
                    });
                    interface
                }
            };
            Some(interface)
        }
    };
    writer
        .write_frame(&frame)
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

pub(in crate::cli) fn replay_cli_error(error: workflow::replay::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
