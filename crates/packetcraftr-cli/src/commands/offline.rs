// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline build, dissect, and capture-read commands.

use std::fs::File;
use std::io::BufReader;
use std::time::SystemTime;

use packetcraftr::{
    capture::{self, Frame, Limits, LinkType, Reader, ReaderOptions, transcode},
    error::{Classification, Kind},
    output, packet,
};

use super::super::arguments::{
    BuildArgs, CaptureStreamLimitArgs, CliBuildMode, DissectArgs, ReadArgs,
};
use super::super::errors::CliError;
use super::super::input::{read_bounded_file, read_recipe, read_stdin_bounded};
use super::super::rendering::{
    CaptureSink, capture_file_format, capture_sink_path, emit_json, emit_json_compact, spaced_hex,
    write_bytes, write_plain_line, write_stdout_line,
};
use super::super::runtime::default_registry_arc;

/// Buffer size for capture-file reads. `Reader` pulls one block header and one
/// payload at a time, so an unbuffered file would issue two syscalls per frame.
pub(crate) const READ_BUFFER_BYTES: usize = 128 * 1024;

/// Opens a capture file for bounded streaming with buffered reads.
pub(crate) fn open_capture_reader(
    path: &std::path::Path,
    max_frame_bytes: usize,
    max_interfaces: usize,
) -> Result<Reader<BufReader<File>>, CliError> {
    let file = File::open(path)
        .map_err(|source| CliError::new(5, format!("open {} failed: {source}", path.display())))?;
    Reader::with_options(
        BufReader::with_capacity(READ_BUFFER_BYTES, file),
        ReaderOptions {
            max_size: max_frame_bytes,
            max_interfaces_per_section: max_interfaces,
            ..ReaderOptions::default()
        },
    )
    .map_err(CliError::classified)
}

pub(crate) fn run_build(
    arguments: BuildArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    let packet = read_recipe(arguments.recipe, &registry)?;
    let built = packet::build::Builder::new(registry)
        .build(
            packet,
            packet::build::Context::default(),
            packet::build::Options {
                mode: match arguments.mode {
                    CliBuildMode::Strict => packet::build::Mode::Strict,
                    CliBuildMode::Permissive => packet::build::Mode::Permissive,
                },
                ..packet::build::Options::default()
            },
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = output::build::Result::from_built(built);
    match output {
        output::contract::Format::Text => {
            write_stdout_line(format_args!("built {} bytes", result.length))?;
            write_stdout_line(format_args!("{}", spaced_hex(result.bytes())))?;
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        output::contract::Format::Hex => write_plain_line(format_args!("{}", result.bytes_hex)),
        output::contract::Format::Raw => write_bytes(result.bytes(), None),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Build,
            result,
            diagnostics,
        )),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Build,
                format: output,
            },
        )),
    }
}

pub(crate) fn run_dissect(
    arguments: DissectArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let bytes = match (arguments.hex, arguments.file) {
        (Some(value), None) => packet::expression::decode_hex(&value)
            .map_err(|source| CliError::new(2, source.to_string()))?
            .to_vec(),
        (None, Some(path)) => {
            read_bounded_file(&path, packet::document::DEFAULT_MAX_DOCUMENT_BYTES)?
        }
        (None, None) => read_stdin_bounded(packet::document::DEFAULT_MAX_DOCUMENT_BYTES)?,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let registry = default_registry_arc()?;
    let decoded = packet::decode::Decoder::new(registry)
        .decode(
            Frame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
                .map_err(|source| CliError::new(3, source.to_string()))?,
            packet::decode::Options::default(),
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = output::dissect::Result::from_decoded(decoded);
    match output {
        output::contract::Format::Text => {
            write_stdout_line(format_args!(
                "decoded {} bytes into {} layer(s)",
                result.length,
                result.packet.layers.len()
            ))?;
            for (index, layer) in result.packet.layers.iter().enumerate() {
                write_stdout_line(format_args!("{index}: {}", layer.protocol))?;
            }
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        output::contract::Format::Hex => write_plain_line(format_args!("{}", result.bytes_hex)),
        output::contract::Format::Raw => write_bytes(result.bytes(), None),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Dissect,
            result,
            diagnostics,
        )),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Dissect,
                format: output,
            },
        )),
    }
}

pub(crate) fn run_read(
    arguments: ReadArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let ReadArgs {
        path,
        limits:
            CaptureStreamLimitArgs {
                max_frames,
                max_bytes,
                max_frame_bytes,
                max_interfaces,
            },
        sink,
    } = arguments;
    validate_capture_stream_limits(max_frames, max_bytes, max_frame_bytes, max_interfaces)?;
    let destination = capture_sink_path(sink.write, output)?;
    let mut reader = open_capture_reader(&path, max_frame_bytes, max_interfaces)?;
    let stream_limits = Limits {
        max_frames,
        max_bytes,
    };
    if matches!(
        output,
        output::contract::Format::Pcap | output::contract::Format::Pcapng
    ) {
        let format = capture_file_format(output)?;
        let (sink, _report) = transcode(
            &mut reader,
            CaptureSink::open(destination.as_deref())?,
            format,
            stream_limits,
        )
        .map_err(CliError::classified)?;
        return sink.finish();
    }

    let mut sequence = 0_u64;
    let mut captured_bytes = 0_u64;
    let mut aggregate = Vec::new();
    loop {
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| CliError::classified(source).at_sequence(sequence))?
        else {
            break;
        };
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(sequence)
        })?;
        if next_sequence > max_frames {
            return Err(CliError::classified(capture::Error::FrameLimitExceeded {
                actual: next_sequence,
                limit: max_frames,
            })
            .at_sequence(sequence));
        }
        let next_bytes = captured_bytes
            .checked_add(u64::from(frame.captured_length()))
            .ok_or_else(|| {
                CliError::classified(capture::Error::StreamByteLimitExceeded {
                    actual: u64::MAX,
                    limit: max_bytes,
                })
                .at_sequence(sequence)
            })?;
        if next_bytes > max_bytes {
            return Err(
                CliError::classified(capture::Error::StreamByteLimitExceeded {
                    actual: next_bytes,
                    limit: max_bytes,
                })
                .at_sequence(sequence),
            );
        }
        let result = output::capture::Read::try_from_frame(frame)
            .map_err(|source| CliError::classified(source).at_sequence(sequence))?;
        match output {
            output::contract::Format::Text => write_stdout_line(format_args!(
                "{sequence}: dlt={} caplen={} wirelen={} {}",
                result.frame.link_type,
                result.frame.captured_length,
                result.frame.original_length,
                spaced_hex(result.frame.bytes())
            ))?,
            output::contract::Format::Hex => {
                write_plain_line(format_args!("{}", result.frame.bytes_hex))?
            }
            output::contract::Format::Ndjson => {
                emit_json_compact(&output::envelope::Stream::success(
                    output::contract::Command::Read,
                    sequence,
                    result,
                    Vec::new(),
                ))
                .map_err(|error| error.at_sequence(sequence))?
            }
            output::contract::Format::Json => aggregate.push(result.frame),
            _ => {
                return Err(CliError::classified(
                    output::contract::Error::UnsupportedFormat {
                        command: output::contract::Command::Read,
                        format: output,
                    },
                ));
            }
        }
        sequence = next_sequence;
        captured_bytes = next_bytes;
    }

    if matches!(output, output::contract::Format::Json) {
        return emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Read,
            output::capture::ReadResult {
                frames: aggregate,
                count: sequence,
            },
            Vec::new(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_capture_stream_limits(
    max_frames: u64,
    max_bytes: u64,
    max_frame_bytes: usize,
    max_interfaces: usize,
) -> Result<(), CliError> {
    if max_frames == 0 || max_bytes == 0 || max_frame_bytes == 0 || max_interfaces == 0 {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_limit",
                Kind::Cli,
                Some("use finite non-zero capture frame, byte, packet, and interface limits"),
            ),
            "capture stream limits must be non-zero",
            Vec::new(),
        ));
    }
    if u64::try_from(max_frame_bytes).unwrap_or(u64::MAX) > max_bytes {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_limit",
                Kind::Cli,
                Some("set max-frame-bytes no higher than the aggregate max-bytes budget"),
            ),
            format!("max-frame-bytes {max_frame_bytes} exceeds max-bytes {max_bytes}"),
            Vec::new(),
        ));
    }
    Ok(())
}
