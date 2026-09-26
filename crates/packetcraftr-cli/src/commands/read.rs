// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Read CLI command logic.

pub(super) mod arguments;
pub(crate) mod rendering;
#[cfg(test)]
mod tests;

use packetcraftr_cli::output::contract::ReadFormat;

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use packetcraftr_core as core;
use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::Limits;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::capture_file::rewrite;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;

use packetcraftr_cli::output;

use self::arguments::Args;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::FrameDecoder;
use crate::input::{open_capture, validate_capture_stream_limits};
use crate::rendering::{StreamEncoder, finish_compressed_output};

use super::increment_counter;
use rendering::render_record;

/// The decoding one `read` invocation needs, built only when `--filter` or
/// `--dissect` asks for it.
struct Decoding {
    frames: FrameDecoder,
    /// Whether the decoded stack is published, not merely used to filter.
    publish_layers: bool,
}

#[derive(Default)]
struct StreamState {
    frames_read: u64,
    frames_matched: u64,
    captured_bytes_read: u64,
}

pub(super) fn run(
    arguments: Args,
    format: ReadFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    arguments.compression.validate(format.as_format())?;
    if !arguments.fields.is_empty() {
        return super::projection::read(arguments, format.as_format(), stream);
    }
    if matches!(format, ReadFormat::Json | ReadFormat::Csv | ReadFormat::Tsv) {
        return Err(super::projection::missing_fields_error());
    }
    let Args {
        fields: _,
        max_projection_bytes: _,
        compression,
        path,
        limits,
        epoch,
        filter,
        normalize,
        dissect,
        decode,
    } = arguments;
    validate_capture_stream_limits(limits)?;
    let bounds = epoch.resolve()?;
    validate_dissect_format(dissect, format)?;
    if normalize && format != ReadFormat::PcapNg {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_normalize_format",
                Kind::Cli,
                Some("use --normalize with --output pcapng"),
            ),
            "--normalize requires PCAPNG output",
            Vec::new(),
        ));
    }
    let rewrite_format = match format {
        ReadFormat::Pcap => Some(capture::Format::Pcap),
        ReadFormat::PcapNg => Some(capture::Format::PcapNg),
        _ => None,
    };
    let decoding = prepare_decoding(
        filter.as_deref(),
        dissect,
        &decode,
        limits.reader.max_frame_bytes,
    )?;
    let mut reader = open_capture(&path, limits.reader)?;
    if normalize {
        let stdout = io::stdout();
        let mut destination = compression.writer(stdout.lock())?;
        let result = normalize_capture(
            &mut reader,
            limits,
            bounds,
            decoding.as_ref(),
            &mut destination,
        );
        return finish_compressed_output(result, destination);
    }
    if let Some(rewrite_format) = rewrite_format {
        validate_rewrite_format(reader.format(), rewrite_format)?;
        let stream_limits = Limits {
            max_frames: limits.max_frames,
            max_bytes: limits.max_bytes,
        };
        let stdout = io::stdout();
        let mut destination = compression.writer(stdout.lock())?;
        let result = rewrite_capture(
            &mut reader,
            stream_limits,
            bounds,
            decoding.as_ref(),
            &mut destination,
        );
        return finish_compressed_output(result, destination);
    }
    read_records(
        &mut reader,
        limits,
        bounds,
        decoding.as_ref(),
        format,
        stream,
    )
}

fn validate_dissect_format(dissect: bool, format: ReadFormat) -> Result<(), CliError> {
    if dissect && !matches!(format, ReadFormat::Text | ReadFormat::Ndjson) {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.dissect_unsupported_format",
                Kind::Cli,
                Some("use --output text or --output ndjson to show the layer stack"),
            ),
            format!("--dissect has no effect on {format} output"),
            Vec::new(),
        ));
    }
    Ok(())
}

fn prepare_decoding(
    filter: Option<&str>,
    dissect: bool,
    decode: &crate::command_options::DecodeArgs,
    max_frame_bytes: usize,
) -> Result<Option<Decoding>, CliError> {
    let registry = decode.registry()?;
    if filter.is_none() && !dissect {
        return Ok(None);
    }
    Ok(Some(Decoding {
        frames: FrameDecoder::compile(&registry, filter, max_frame_bytes)?,
        publish_layers: dissect,
    }))
}

/// Whether epoch bounds keep `frame`; absent bounds keep everything, and a
/// frame without a timestamp is never kept while bounds are set.
fn kept_by_time(bounds: Option<core::frame::TimeBounds>, frame: &core::frame::Frame) -> bool {
    bounds.is_none_or(|bounds| bounds.contains(frame.timestamp))
}

/// Checked before stdout is wrapped, so a rejected conversion writes no
/// compressed container.
fn validate_rewrite_format(
    input: capture::Format,
    output: capture::Format,
) -> Result<(), CliError> {
    if output != input {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_rewrite_format",
                Kind::Cli,
                Some("select the capture output format matching the input capture"),
            ),
            format!(
                "capture rewriting cannot convert {input} input to {output} without normalization"
            ),
            Vec::new(),
        ));
    }
    Ok(())
}

fn rewrite_capture(
    reader: &mut Reader<impl Read>,
    limits: Limits,
    bounds: Option<core::frame::TimeBounds>,
    decoding: Option<&Decoding>,
    destination: &mut impl Write,
) -> Result<(), CliError> {
    if decoding.is_none() && bounds.is_none() {
        return rewrite(reader, destination, limits)
            .map(|_| ())
            .map_err(CliError::classified);
    }
    capture::select(reader, destination, limits, |number, frame| {
        if !kept_by_time(bounds, frame) {
            return Ok(false);
        }
        let Some(decoding) = decoding else {
            return Ok(true);
        };
        decoding
            .frames
            .decode_selected(number, frame)
            .map(|decoded| decoded.is_some())
            .map_err(CliError::into_boundary_error)
    })
    .map(|_| ())
    .map_err(CliError::classified)
}

fn read_records(
    reader: &mut Reader<impl Read>,
    limits: OfflineCaptureLimitsArgs,
    bounds: Option<core::frame::TimeBounds>,
    decoding: Option<&Decoding>,
    format: ReadFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let mut state = StreamState::default();
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        let source_frame = account_frame(&mut state, &frame, limits)?;
        if !kept_by_time(bounds, &frame) {
            continue;
        }
        let Some(record) = convert_frame(frame, source_frame, decoding)? else {
            continue;
        };
        render_record(record, format, stream)?;
        state.frames_matched = increment_counter(state.frames_matched, "read matched-frame count")?;
    }
    if format == ReadFormat::Ndjson {
        stream.complete(
            output::read::Event::Complete {
                frames_read: state.frames_read,
                frames_matched: state.frames_matched,
                captured_bytes_read: state.captured_bytes_read,
            },
            Vec::new(),
        )?;
    }
    Ok(())
}

fn normalize_capture(
    reader: &mut Reader<impl Read>,
    limits: OfflineCaptureLimitsArgs,
    bounds: Option<core::frame::TimeBounds>,
    decoding: Option<&Decoding>,
    destination: impl Write,
) -> Result<(), CliError> {
    let mut writer = capture::Writer::pcapng_with_options(
        destination,
        capture::PcapNgOptions {
            max_size: limits.reader.max_frame_bytes,
            max_interfaces: limits.reader.max_interfaces,
            stream_limits: Limits {
                max_frames: limits.max_frames,
                max_bytes: limits.max_bytes,
            },
            ..capture::PcapNgOptions::default()
        },
    )
    .map_err(CliError::classified)?;
    let mut interfaces = BTreeMap::new();
    let mut state = StreamState::default();
    while let Some(mut frame) = reader.next_frame().map_err(CliError::classified)? {
        let source_frame = account_frame(&mut state, &frame, limits)?;
        if !kept_by_time(bounds, &frame) {
            continue;
        }
        if let Some(decoding) = decoding
            && decoding
                .frames
                .decode_selected(source_frame, &frame)?
                .is_none()
        {
            continue;
        }
        // Classic PCAP exposes its single interface at zero; PCAPNG frame IDs are global.
        let source_interface = frame.interface.unwrap_or(0);
        let output_interface = match interfaces.get(&source_interface) {
            Some(interface) => *interface,
            None => {
                let source_index = usize::try_from(source_interface)
                    .expect("reader interface IDs fit the in-memory interface table");
                let description = reader
                    .interfaces()
                    .get(source_index)
                    .expect("reader registers each frame interface before returning the frame")
                    .clone();
                let output_interface = writer
                    .add_interface_description(description)
                    .map_err(CliError::classified)?;
                interfaces.insert(source_interface, output_interface);
                output_interface
            }
        };
        frame.interface = Some(output_interface);
        writer.write_frame(&frame).map_err(CliError::classified)?;
    }
    writer.flush().map_err(CliError::classified)
}

/// Charges one frame against the same two aggregate ceilings the rewrite copy
/// and the analysis loop charge against, and answers with its source number.
fn account_frame(
    state: &mut StreamState,
    frame: &core::frame::Frame,
    limits: OfflineCaptureLimitsArgs,
) -> Result<u64, CliError> {
    crate::cancellation::check()?;
    let stream_limits = Limits {
        max_frames: limits.max_frames,
        max_bytes: limits.max_bytes,
    };
    let (frames_read, captured_bytes_read) = stream_limits
        .advance(
            state.frames_read,
            state.captured_bytes_read,
            frame.captured_length(),
        )
        .map_err(CliError::classified)?;
    state.frames_read = frames_read;
    state.captured_bytes_read = captured_bytes_read;
    Ok(state.frames_read)
}

fn convert_frame(
    frame: core::frame::Frame,
    source_frame: u64,
    decoding: Option<&Decoding>,
) -> Result<Option<output::read::Frame>, CliError> {
    let Some(decoding) = decoding else {
        return output::read::Frame::try_from_frame(source_frame, frame)
            .map(Some)
            .map_err(CliError::classified);
    };
    let Some(decoded) = decoding.frames.decode_selected(source_frame, &frame)? else {
        return Ok(None);
    };
    if decoding.publish_layers {
        output::read::Frame::try_from_decoded(source_frame, frame, &decoded)
    } else {
        output::read::Frame::try_from_frame(source_frame, frame)
    }
    .map(Some)
    .map_err(CliError::classified)
}
