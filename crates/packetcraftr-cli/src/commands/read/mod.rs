// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Read CLI command logic.

pub(super) mod arguments;
mod rendering;

use std::fs::File;
use std::io;

use packetcraftr::{
    analysis::pcap::{Limits, Reader, rewrite},
    core::{
        self,
        error::{Classification, Kind},
    },
    output,
};

use self::arguments::Args;
use super::registry_with_tls_ports;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{open_capture, validate_capture_stream_limits};
use crate::rendering::{NdjsonStream, capture_file_format};

use super::increment_counter;
use rendering::render_record;

struct Decoding {
    decoder: core::decode::Dissector,
    filter: Option<core::filter::Filter>,
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
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let Args {
        path,
        limits,
        filter,
        dissect,
        tls_ports,
    } = arguments;
    validate_limits(limits)?;
    validate_dissect_format(dissect, format)?;
    let decoding = prepare_decoding(filter.as_deref(), dissect, &tls_ports.ports)?;
    let mut reader = open_capture(&path, limits)?;
    let stream_limits = Limits {
        max_frames: limits.max_frames,
        max_bytes: limits.max_bytes,
    };

    if matches!(
        format,
        output::contract::Format::Pcap | output::contract::Format::PcapNg
    ) {
        return rewrite_capture(&mut reader, format, stream_limits, filter.is_some());
    }
    read_records(
        &mut reader,
        limits,
        decoding.as_ref(),
        dissect,
        format,
        stream,
    )
}

fn validate_limits(limits: OfflineCaptureLimitsArgs) -> Result<(), CliError> {
    validate_capture_stream_limits(
        limits.max_frames,
        limits.max_bytes,
        limits.max_frame_bytes,
        limits.max_interfaces,
    )
}

fn validate_dissect_format(
    dissect: bool,
    format: output::contract::Format,
) -> Result<(), CliError> {
    if dissect
        && !matches!(
            format,
            output::contract::Format::Text | output::contract::Format::Ndjson
        )
    {
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
    }))
}

fn rewrite_capture(
    reader: &mut Reader<File>,
    format: output::contract::Format,
    limits: Limits,
    filtered: bool,
) -> Result<(), CliError> {
    if filtered {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_rewrite_filter",
                Kind::Cli,
                Some("use text, hex, or ndjson output to filter frames"),
            ),
            "capture rewriting cannot filter records without discarding source structure",
            Vec::new(),
        ));
    }
    let format = capture_file_format(format)?;
    if format != reader.format() {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_rewrite_format",
                Kind::Cli,
                Some("select the capture output format matching the input capture"),
            ),
            format!(
                "capture rewriting cannot convert {:?} input to {format:?} without normalization",
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
    dissect: bool,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let mut state = StreamState::default();
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        let source_frame = account_frame(&mut state, &frame, limits)?;
        let Some(event) = convert_frame(frame, source_frame, decoding, dissect, limits)? else {
            continue;
        };
        render_record(&event, format, stream)?;
        state.frames_matched = increment_counter(state.frames_matched, "read matched-frame count")?;
    }
    if format == output::contract::Format::Ndjson {
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

fn account_frame(
    state: &mut StreamState,
    frame: &core::frame::Frame,
    limits: OfflineCaptureLimitsArgs,
) -> Result<u64, CliError> {
    state.frames_read = increment_counter(state.frames_read, "read frame count")?;
    if state.frames_read > limits.max_frames {
        return Err(CliError::classified(
            packetcraftr::analysis::pcap::Error::FrameLimitExceeded {
                actual: state.frames_read,
                limit: limits.max_frames,
            },
        ));
    }
    state.captured_bytes_read = state
        .captured_bytes_read
        .checked_add(u64::from(frame.captured_length()))
        .ok_or_else(|| stream_byte_error(u64::MAX, limits.max_bytes))?;
    if state.captured_bytes_read > limits.max_bytes {
        return Err(stream_byte_error(
            state.captured_bytes_read,
            limits.max_bytes,
        ));
    }
    Ok(state.frames_read)
}

fn stream_byte_error(actual: u64, limit: u64) -> CliError {
    CliError::classified(
        packetcraftr::analysis::pcap::Error::StreamByteLimitExceeded { actual, limit },
    )
}

fn convert_frame(
    frame: core::frame::Frame,
    source_frame: u64,
    decoding: Option<&Decoding>,
    dissect: bool,
    limits: OfflineCaptureLimitsArgs,
) -> Result<Option<output::read::Event>, CliError> {
    let Some(decoding) = decoding else {
        return output::read::Event::try_from_frame(source_frame, frame)
            .map(Some)
            .map_err(CliError::classified);
    };
    let decoded = decoding
        .decoder
        .decode(
            frame.clone(),
            core::decode::Options {
                max_packet_size: limits.max_frame_bytes,
                ..core::decode::Options::default()
            },
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    if let Some(filter) = &decoding.filter {
        validate_filter_timestamp(filter, &frame, source_frame)?;
        if !filter
            .matches(&core::filter::Context {
                decoded: &decoded,
                number: source_frame,
                tcp_stream: None,
                udp_stream: None,
            })
            .map_err(|source| CliError::new(3, source.to_string()))?
        {
            return Ok(None);
        }
    }
    if dissect {
        output::read::Event::try_from_decoded(source_frame, frame, &decoded)
    } else {
        output::read::Event::try_from_frame(source_frame, frame)
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
