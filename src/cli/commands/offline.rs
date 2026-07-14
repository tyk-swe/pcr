// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline build, dissect, and capture-read commands.

use std::fs::File;
use std::io;
use std::time::SystemTime;

use packetcraftr::{
    capture::{self, Frame, Limits, LinkType, Reader, transcode},
    error::{Classification, Kind},
    output, packet,
};

use super::super::arguments::{BuildArgs, CliBuildMode, DissectArgs, ReadArgs};
use super::super::errors::CliError;
use super::super::input::{read_bounded_file, read_recipe, read_stdin_bounded};
use super::super::rendering::{
    capture_file_format, emit_json, emit_json_compact, spaced_hex, write_raw, write_stdout_line,
};
use super::super::runtime::default_registry_arc;

pub(in crate::cli) fn run_build(
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
        output::contract::Format::Hex => write_stdout_line(format_args!("{}", result.bytes_hex)),
        output::contract::Format::Raw => write_raw(result.bytes()),
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

pub(in crate::cli) fn run_dissect(
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
        output::contract::Format::Hex => write_stdout_line(format_args!("{}", result.bytes_hex)),
        output::contract::Format::Raw => write_raw(result.bytes()),
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

pub(in crate::cli) fn run_read(
    arguments: ReadArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let ReadArgs {
        path,
        max_frames,
        max_bytes,
        max_frame_bytes,
        max_interfaces,
    } = arguments;
    validate_capture_stream_limits(max_frames, max_bytes, max_frame_bytes, max_interfaces)?;
    let file = File::open(&path)
        .map_err(|source| CliError::new(5, format!("open {} failed: {source}", path.display())))?;
    let mut reader =
        Reader::with_limits(file, max_frame_bytes, max_interfaces).map_err(CliError::classified)?;
    let stream_limits = Limits {
        max_frames,
        max_bytes,
    };
    if matches!(
        output,
        output::contract::Format::Pcap | output::contract::Format::Pcapng
    ) {
        let format = capture_file_format(output)?;
        let stdout = io::stdout();
        let (_output, _report) = transcode(&mut reader, stdout.lock(), format, stream_limits)
            .map_err(CliError::classified)?;
        return Ok(());
    }

    let mut sequence = 0_u64;
    let mut captured_bytes = 0_u64;
    loop {
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| CliError::classified(source).at_sequence(sequence))?
        else {
            return Ok(());
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
                write_stdout_line(format_args!("{}", result.frame.bytes_hex))?
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
}

pub(in crate::cli) fn validate_capture_stream_limits(
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
