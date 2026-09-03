// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Read CLI command logic.

pub(super) mod arguments;
mod rendering;

use std::fs::File;
use std::io;

use packetcraftr::{
    analysis::pcap::{self as capture, Limits, Reader, rewrite},
    core::{
        self,
        error::{Classification, Kind},
    },
    output,
};

use self::arguments::Args;
use super::format::{CaptureFormat, FrameFormat};
use super::registry_with_tls_ports;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{open_capture, validate_capture_stream_limits};
use crate::rendering::StreamEncoder;

use super::increment_counter;
use rendering::render_record;

/// The decoding one `read` invocation needs, built only when `--filter` or
/// `--dissect` asks for it.
struct Decoding {
    decoder: core::decode::Dissector,
    filter: Option<core::filter::Filter>,
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
    format: output::contract::Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let Args {
        path,
        limits,
        filter,
        dissect,
        tls_ports,
    } = arguments;
    let format = CaptureFormat::narrow(output::contract::Command::Read, format)?;
    validate_capture_stream_limits(limits)?;
    // Both rejections precede filter compilation, so an incompatible request
    // is answered with the incompatibility, not a filter syntax error.
    validate_dissect_format(dissect, format)?;
    let rewrite_format = match format {
        CaptureFormat::Pcap => Some(capture::Format::Pcap),
        CaptureFormat::PcapNg => Some(capture::Format::PcapNg),
        CaptureFormat::Text | CaptureFormat::Ndjson | CaptureFormat::Hex => None,
    };
    if rewrite_format.is_some() && filter.is_some() {
        return Err(capture_rewrite_filter_error());
    }
    let decoding = prepare_decoding(filter.as_deref(), dissect, &tls_ports.ports)?;
    let mut reader = open_capture(&path, limits.reader_bounds())?;
    if let Some(rewrite_format) = rewrite_format {
        let stream_limits = Limits {
            max_frames: limits.max_frames,
            max_bytes: limits.max_bytes,
        };
        return rewrite_capture(&mut reader, rewrite_format, stream_limits);
    }
    let format = FrameFormat::narrow_from(output::contract::Command::Read, format)?;
    read_records(&mut reader, limits, decoding.as_ref(), format, stream)
}

fn validate_dissect_format(dissect: bool, format: CaptureFormat) -> Result<(), CliError> {
    if dissect && !matches!(format, CaptureFormat::Text | CaptureFormat::Ndjson) {
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

fn capture_rewrite_filter_error() -> CliError {
    CliError::from_classification(
        Classification::new(
            "cli.capture_rewrite_filter",
            Kind::Cli,
            Some("use text, hex, or ndjson output to filter frames"),
        ),
        "capture rewriting cannot filter records without discarding source structure",
        Vec::new(),
    )
}

fn prepare_decoding(
    filter: Option<&str>,
    dissect: bool,
    tls_ports: &[u16],
) -> Result<Option<Decoding>, CliError> {
    if filter.is_none() && !dissect {
        return Ok(None);
    }
    let registry = registry_with_tls_ports(tls_ports)?;
    let filter = filter
        .map(|source| filtering::compile(source, &registry, Capabilities::frames_only()))
        .transpose()?;
    Ok(Some(Decoding {
        decoder: core::decode::Dissector::new(registry),
        filter,
        publish_layers: dissect,
    }))
}

fn rewrite_capture(
    reader: &mut Reader<File>,
    format: capture::Format,
    limits: Limits,
) -> Result<(), CliError> {
    if format != reader.format() {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_rewrite_format",
                Kind::Cli,
                Some("select the capture output format matching the input capture"),
            ),
            format!(
                "capture rewriting cannot convert {} input to {format} without normalization",
                reader.format()
            ),
            Vec::new(),
        ));
    }
    let stdout = io::stdout();
    rewrite(reader, stdout.lock(), limits)
        .map(|_| ())
        .map_err(CliError::classified)
}

fn read_records(
    reader: &mut Reader<File>,
    limits: OfflineCaptureLimitsArgs,
    decoding: Option<&Decoding>,
    format: FrameFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let mut state = StreamState::default();
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        let source_frame = account_frame(&mut state, &frame, limits)?;
        let Some(record) = convert_frame(frame, source_frame, decoding, limits)? else {
            continue;
        };
        render_record(record, format, stream)?;
        state.frames_matched = increment_counter(state.frames_matched, "read matched-frame count")?;
    }
    if format == FrameFormat::Ndjson {
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

/// Charges one frame against the same two aggregate ceilings the rewrite copy
/// and the analysis loop charge against, and answers with its source number.
fn account_frame(
    state: &mut StreamState,
    frame: &core::frame::Frame,
    limits: OfflineCaptureLimitsArgs,
) -> Result<u64, CliError> {
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
    limits: OfflineCaptureLimitsArgs,
) -> Result<Option<output::read::Frame>, CliError> {
    let Some(decoding) = decoding else {
        return output::read::Frame::try_from_frame(source_frame, frame)
            .map(Some)
            .map_err(CliError::classified);
    };
    let decoded = decoding
        .decoder
        .decode(
            frame.clone(),
            core::decode::Options {
                max_packet_size: limits.reader.max_frame_bytes,
                ..core::decode::Options::default()
            },
        )
        .map_err(CliError::classified)?;
    if let Some(filter) = &decoding.filter {
        validate_filter_timestamp(filter, &frame, source_frame)?;
        if !filter
            .matches(&core::filter::Context {
                decoded: &decoded,
                derived: &[],
                number: source_frame,
                tcp_stream: None,
                udp_stream: None,
            })
            .map_err(|source| CliError::new(Kind::Packet, source.to_string()))?
        {
            return Ok(None);
        }
    }
    if decoding.publish_layers {
        output::read::Frame::try_from_decoded(source_frame, frame, &decoded)
    } else {
        output::read::Frame::try_from_frame(source_frame, frame)
    }
    .map(Some)
    .map_err(CliError::classified)
}

fn validate_filter_timestamp(
    filter: &core::filter::Filter,
    frame: &core::frame::Frame,
    source_frame: u64,
) -> Result<(), CliError> {
    if filter.requirements().timestamp && frame.timestamp.is_none() {
        return Err(CliError::from_classification(
            Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("remove frame.time_epoch from the filter or use timestamped packet blocks"),
            ),
            format!("frame {source_frame} has no timestamp required by frame.time_epoch"),
            Vec::new(),
        ));
    }
    Ok(())
}
