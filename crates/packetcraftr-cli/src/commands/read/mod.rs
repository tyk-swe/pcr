// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Read CLI command logic.

pub(super) mod arguments;
mod conversion;
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
use super::registry;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{open_capture, validate_capture_stream_limits};
use crate::rendering::capture_file_format;

use conversion::{decode_options, increment_counter};
use rendering::render_record;

struct Decoding {
    decoder: core::decode::Dissector,
    filter: Option<core::filter::Filter>,
}

#[derive(Default)]
struct StreamState {
    sequence: u64,
    frames: u64,
    captured_bytes: u64,
}

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let Args {
        path,
        limits,
        filter,
        dissect,
    } = arguments;
    validate_limits(limits)?;
    validate_dissect_format(dissect, format)?;
    let decoding = prepare_decoding(filter.as_deref(), dissect)?;
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
    read_records(&mut reader, limits, decoding.as_ref(), dissect, format)
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

fn prepare_decoding(filter: Option<&str>, dissect: bool) -> Result<Option<Decoding>, CliError> {
    if filter.is_none() && !dissect {
        return Ok(None);
    }
    let registry = registry()?;
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
) -> Result<(), CliError> {
    let mut state = StreamState::default();
    while let Some(frame) = reader
        .next_frame()
        .map_err(|source| CliError::classified(source).at_sequence(state.sequence))?
    {
        let number = account_frame(&mut state, &frame, limits)?;
        let Some(result) = convert_frame(frame, number, state.sequence, decoding, dissect, limits)?
        else {
            continue;
        };
        render_record(&result, format, state.sequence)?;
        state.sequence = increment_counter(state.sequence, state.sequence)?;
    }
    Ok(())
}

fn account_frame(
    state: &mut StreamState,
    frame: &core::frame::Frame,
    limits: OfflineCaptureLimitsArgs,
) -> Result<u64, CliError> {
    state.frames = increment_counter(state.frames, state.sequence)?;
    if state.frames > limits.max_frames {
        return Err(CliError::classified(
            packetcraftr::analysis::pcap::Error::FrameLimitExceeded {
                actual: state.frames,
                limit: limits.max_frames,
            },
        )
        .at_sequence(state.sequence));
    }
    state.captured_bytes = state
        .captured_bytes
        .checked_add(u64::from(frame.captured_length()))
        .ok_or_else(|| stream_byte_error(u64::MAX, limits.max_bytes, state.sequence))?;
    if state.captured_bytes > limits.max_bytes {
        return Err(stream_byte_error(
            state.captured_bytes,
            limits.max_bytes,
            state.sequence,
        ));
    }
    Ok(state.frames)
}

fn stream_byte_error(actual: u64, limit: u64, sequence: u64) -> CliError {
    CliError::classified(
        packetcraftr::analysis::pcap::Error::StreamByteLimitExceeded { actual, limit },
    )
    .at_sequence(sequence)
}

fn convert_frame(
    frame: core::frame::Frame,
    number: u64,
    sequence: u64,
    decoding: Option<&Decoding>,
    dissect: bool,
    limits: OfflineCaptureLimitsArgs,
) -> Result<Option<output::read::Result>, CliError> {
    let Some(decoding) = decoding else {
        return output::read::Result::try_from_frame(frame)
            .map(Some)
            .map_err(|source| CliError::classified(source).at_sequence(sequence));
    };
    let decoded = decoding
        .decoder
        .decode(frame.clone(), decode_options(limits.max_frame_bytes))
        .map_err(|source| CliError::new(3, source.to_string()).at_sequence(sequence))?;
    if let Some(filter) = &decoding.filter {
        validate_filter_timestamp(filter, &frame, number, sequence)?;
        if !filter
            .matches(&core::filter::Context {
                decoded: &decoded,
                number,
                tcp_stream: None,
                udp_stream: None,
            })
            .map_err(|source| CliError::new(3, source.to_string()).at_sequence(sequence))?
        {
            return Ok(None);
        }
    }
    if dissect {
        output::read::Result::try_from_decoded(frame, &decoded)
    } else {
        output::read::Result::try_from_frame(frame)
    }
    .map(Some)
    .map_err(|source| CliError::classified(source).at_sequence(sequence))
}

fn validate_filter_timestamp(
    filter: &core::filter::Filter,
    frame: &core::frame::Frame,
    number: u64,
    sequence: u64,
) -> Result<(), CliError> {
    if filter.requirements().timestamp && frame.timestamp.is_none() {
        return Err(CliError::from_classification(
            Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("remove frame.time_epoch from the filter or use timestamped packet blocks"),
            ),
            format!("frame {number} has no timestamp required by frame.time_epoch"),
            Vec::new(),
        )
        .at_sequence(sequence));
    }
    Ok(())
}
