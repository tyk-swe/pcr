// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Read CLI command logic.

pub(super) mod arguments;
mod rendering;

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::sync::Arc;

use packetcraftr::{
    analysis::pcap::{Limits, Reader, rewrite},
    core::{
        self,
        error::{Classification, Kind},
    },
    output,
};

use self::arguments::Args;
use super::format::{FrameFormat, ReadFormat};
use super::registry_with_tls_ports;
use crate::command_options::OfflineCaptureLimitsArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{open_capture, validate_capture_stream_limits};
use crate::rendering::{StreamEncoder, capture_file_format, emit_stderr_message, write_plain_line};

use super::increment_counter;
use rendering::render_record;

struct Decoding {
    decoder: core::decode::Dissector,
    filter: Option<core::filter::Filter>,
    registry: Arc<core::registry::Registry>,
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
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    let Args {
        path,
        limits,
        filter,
        dissect,
        columns,
        full,
        tls_ports,
    } = arguments;
    let format = ReadFormat::narrow(output::contract::Command::Read, format)?;
    validate_limits(limits)?;
    validate_dissect_format(dissect, format)?;
    validate_columns_format(!columns.is_empty(), format)?;

    let registry = registry_with_tls_ports(&tls_ports.ports)?;
    let mut parsed_columns = Vec::with_capacity(columns.len());
    for col_str in &columns {
        let field_path = core::filter::FieldPath::parse(col_str, &registry).map_err(|_| {
            CliError::from_classification(
                Classification::new(
                    "cli.unknown_path",
                    Kind::Cli,
                    Some("run `packetcraftr protocols <P>` to list fields"),
                ),
                format!("unknown path `{col_str}`"),
                Vec::new(),
            )
        })?;
        parsed_columns.push((col_str.clone(), field_path));
    }

    let decoding = prepare_decoding(
        filter.as_deref(),
        dissect || format == ReadFormat::Document || !parsed_columns.is_empty(),
        registry,
    )?;
    let mut reader = open_capture(&path, limits)?;
    let stream_limits = Limits {
        max_frames: limits.max_frames,
        max_bytes: limits.max_bytes,
    };

    match format {
        ReadFormat::Pcap | ReadFormat::PcapNg => rewrite_capture(
            &mut reader,
            format.format(),
            stream_limits,
            filter.is_some(),
        ),
        ReadFormat::Document => {
            let decoding = decoding.expect("document mode requires decoding");
            read_documents(&mut reader, limits, &decoding, full)
        }
        ReadFormat::Text => read_records(
            &mut reader,
            limits,
            decoding.as_ref(),
            dissect,
            &parsed_columns,
            FrameFormat::Text,
            stream,
        ),
        ReadFormat::Ndjson => read_records(
            &mut reader,
            limits,
            decoding.as_ref(),
            dissect,
            &parsed_columns,
            FrameFormat::Ndjson,
            stream,
        ),
        ReadFormat::Hex => read_records(
            &mut reader,
            limits,
            decoding.as_ref(),
            dissect,
            &parsed_columns,
            FrameFormat::Hex,
            stream,
        ),
    }
}

fn validate_limits(limits: OfflineCaptureLimitsArgs) -> Result<(), CliError> {
    validate_capture_stream_limits(
        limits.max_frames,
        limits.max_bytes,
        limits.max_frame_bytes,
        limits.max_interfaces,
    )
}

fn validate_dissect_format(dissect: bool, format: ReadFormat) -> Result<(), CliError> {
    if dissect
        && !matches!(
            format,
            ReadFormat::Text | ReadFormat::Ndjson | ReadFormat::Document
        )
    {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.dissect_unsupported_format",
                Kind::Cli,
                Some("use --output text or --output ndjson to show the layer stack"),
            ),
            format!("--dissect has no effect on {} output", format.format()),
            Vec::new(),
        ));
    }
    Ok(())
}

fn validate_columns_format(has_columns: bool, format: ReadFormat) -> Result<(), CliError> {
    if has_columns && !matches!(format, ReadFormat::Text | ReadFormat::Ndjson) {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.columns_unsupported_format",
                Kind::Cli,
                Some("use --output text or --output ndjson with --columns"),
            ),
            format!("--columns has no effect on {} output", format.format()),
            Vec::new(),
        ));
    }
    Ok(())
}

fn prepare_decoding(
    filter: Option<&str>,
    needs_decoding: bool,
    registry: Arc<core::registry::Registry>,
) -> Result<Option<Decoding>, CliError> {
    if filter.is_none() && !needs_decoding {
        return Ok(None);
    }
    let filter = filter
        .map(|source| filtering::compile(source, &registry, Capabilities::frames_only()))
        .transpose()?;
    Ok(Some(Decoding {
        decoder: core::decode::Dissector::new(Arc::clone(&registry)),
        filter,
        registry,
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

fn read_documents(
    reader: &mut Reader<File>,
    limits: OfflineCaptureLimitsArgs,
    decoding: &Decoding,
    full: bool,
) -> Result<(), CliError> {
    let mut state = StreamState::default();
    let mut minimized_count = 0_u64;
    let mut full_literals_count = 0_u64;
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        let source_frame = account_frame(&mut state, &frame, limits)?;
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
                continue;
            }
        }
        state.frames_matched = increment_counter(state.frames_matched, "read matched-frame count")?;
        let (doc, status) =
            core::document::v2::Document::from_decoded(&decoded, &decoding.registry, full);
        match status {
            core::document::v2::Minimized::Derived => {
                minimized_count = increment_counter(minimized_count, "minimized frame count")?;
            }
            core::document::v2::Minimized::FullLiterals => {
                full_literals_count =
                    increment_counter(full_literals_count, "full literals frame count")?;
            }
            core::document::v2::Minimized::Skipped => {}
        }
        let yaml = doc
            .to_yaml_string()
            .map_err(|source| CliError::new(2, source.to_string()))?;
        write_plain_line(format_args!("---\n{}", yaml.trim_end()))?;
        for diag in &decoded.diagnostics {
            emit_stderr_message(&format!(
                "{:?} {}: {}",
                diag.severity, diag.code, diag.message
            ))?;
        }
    }
    emit_stderr_message(&format!(
        "minimized {minimized_count} frame(s), {full_literals_count} with literal derived fields"
    ))?;
    Ok(())
}

fn read_records(
    reader: &mut Reader<File>,
    limits: OfflineCaptureLimitsArgs,
    decoding: Option<&Decoding>,
    dissect: bool,
    columns: &[(String, core::filter::FieldPath)],
    format: FrameFormat,
    stream: &mut StreamEncoder,
) -> Result<(), CliError> {
    let mut state = StreamState::default();
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        let source_frame = account_frame(&mut state, &frame, limits)?;
        let Some((event, decoded_opt)) =
            convert_frame(frame, source_frame, decoding, dissect, limits)?
        else {
            continue;
        };
        if !columns.is_empty() {
            let decoded = decoded_opt
                .as_ref()
                .expect("columns evaluation requires decoded packet");
            let context = core::filter::Context {
                decoded,
                number: source_frame,
                tcp_stream: None,
                udp_stream: None,
            };
            if format == FrameFormat::Text {
                let mut col_values = Vec::with_capacity(columns.len());
                for (_, path) in columns {
                    let val_str = path
                        .evaluate(&context)
                        .map(|val| core::field::text_form(&val))
                        .unwrap_or_else(|| "-".to_owned());
                    col_values.push(val_str);
                }
                write_plain_line(format_args!("{}", col_values.join("\t")))?;
            } else if format == FrameFormat::Ndjson {
                let mut cols_map = BTreeMap::new();
                for (name, path) in columns {
                    if let Some(val) = path.evaluate(&context) {
                        cols_map.insert(name.clone(), val);
                    }
                }
                let event = event.with_columns(cols_map);
                render_record(&event, format, stream)?;
            }
        } else {
            render_record(&event, format, stream)?;
        }
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
) -> Result<Option<(output::read::Event, Option<core::decode::DecodedPacket>)>, CliError> {
    let Some(decoding) = decoding else {
        return output::read::Event::try_from_frame(source_frame, frame)
            .map(|event| Some((event, None)))
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
    let event = if dissect {
        output::read::Event::try_from_decoded(source_frame, frame, &decoded)
    } else {
        output::read::Event::try_from_frame(source_frame, frame)
    }
    .map_err(CliError::classified)?;
    Ok(Some((event, Some(decoded))))
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
