// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Batch capture-file dissection.

use std::fmt::Write as _;

use packetcraftr::{
    capture::{self, Frame},
    output, packet,
};

use super::super::arguments::{CaptureStreamLimitArgs, DecodeArgs};
use super::super::errors::CliError;
use super::super::rendering::{
    emit_json, emit_json_compact, output_timestamp_text, spaced_hex, write_stdout_line,
};
use super::super::runtime::default_registry_arc;
use super::offline::{open_capture_reader, validate_capture_stream_limits};

pub(crate) fn run_decode(
    arguments: DecodeArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let DecodeArgs {
        path,
        verbose,
        limits:
            CaptureStreamLimitArgs {
                max_frames,
                max_bytes,
                max_frame_bytes,
                max_interfaces,
            },
    } = arguments;
    validate_capture_stream_limits(max_frames, max_bytes, max_frame_bytes, max_interfaces)?;
    let registry = default_registry_arc()?;
    let decoder = packet::decode::Decoder::new(registry);
    let decode_options = packet::decode::Options {
        max_packet_size: max_frame_bytes,
        ..packet::decode::Options::default()
    };
    let mut reader = open_capture_reader(&path, max_frame_bytes, max_interfaces)?;

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
        captured_bytes = next_captured_bytes(captured_bytes, &frame, max_bytes, sequence)?;

        let decoded = decoder
            .decode(frame, decode_options.clone())
            .map_err(|source| CliError::new(3, source.to_string()).at_sequence(sequence))?;
        match output {
            output::contract::Format::Text => {
                render_decoded_text(sequence, &decoded, verbose)?;
            }
            output::contract::Format::Ndjson => {
                let decoded = decoded_output(decoded, sequence)?;
                emit_json_compact(&output::envelope::Stream::success(
                    output::contract::Command::Decode,
                    sequence,
                    output::decode::Event::Frame { decoded },
                    Vec::new(),
                ))
                .map_err(|error| error.at_sequence(sequence))?;
            }
            output::contract::Format::Json => aggregate.push(decoded_output(decoded, sequence)?),
            _ => {
                return Err(CliError::classified(
                    output::contract::Error::UnsupportedFormat {
                        command: output::contract::Command::Decode,
                        format: output,
                    },
                ));
            }
        }
        sequence = next_sequence;
    }

    match output {
        output::contract::Format::Text => write_stdout_line(format_args!(
            "decoded {sequence} frame(s), {captured_bytes} byte(s)"
        )),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Decode,
            output::decode::Result {
                frames: aggregate,
                count: sequence,
                filtered: 0,
            },
            Vec::new(),
        )),
        output::contract::Format::Ndjson => emit_json_compact(&output::envelope::Stream::success(
            output::contract::Command::Decode,
            sequence,
            output::decode::Event::Complete {
                frames: sequence,
                filtered: 0,
            },
            Vec::new(),
        ))
        .map_err(|error| error.at_sequence(sequence)),
        _ => unreachable!("unsupported formats are rejected inside the frame loop"),
    }
}

fn next_captured_bytes(
    captured_bytes: u64,
    frame: &Frame,
    max_bytes: u64,
    sequence: u64,
) -> Result<u64, CliError> {
    let next = captured_bytes
        .checked_add(u64::from(frame.captured_length()))
        .ok_or_else(|| {
            CliError::classified(capture::Error::StreamByteLimitExceeded {
                actual: u64::MAX,
                limit: max_bytes,
            })
            .at_sequence(sequence)
        })?;
    if next > max_bytes {
        return Err(
            CliError::classified(capture::Error::StreamByteLimitExceeded {
                actual: next,
                limit: max_bytes,
            })
            .at_sequence(sequence),
        );
    }
    Ok(next)
}

fn decoded_output(
    decoded: packet::decode::Result,
    sequence: u64,
) -> Result<output::frame::Decoded, CliError> {
    output::frame::Decoded::try_from_decoded(decoded)
        .map_err(|source| CliError::classified(source).at_sequence(sequence))
}

/// Renders one decoded frame as a summary line, optionally followed by an
/// indented dump of every reflective layer field.
pub(crate) fn render_decoded_text(
    sequence: u64,
    decoded: &packet::decode::Result,
    verbose: bool,
) -> Result<(), CliError> {
    let timestamp = output::frame::Timestamp::try_from(decoded.frame.timestamp)
        .map_err(|source| CliError::classified(source).at_sequence(sequence))?;
    write_stdout_line(format_args!(
        "{sequence}: {} dlt={} caplen={} wirelen={} {}",
        output_timestamp_text(timestamp),
        decoded.frame.link_type.0,
        decoded.frame.captured_length(),
        decoded.frame.original_length(),
        frame_summary(decoded)
    ))?;
    if !verbose {
        return Ok(());
    }
    for (index, layer) in decoded.packet.iter().enumerate() {
        write_stdout_line(format_args!("  {index} {}{}", layer.protocol_id(), {
            let mut rendered = String::new();
            for field in layer.schema().fields {
                if let Some(value) = layer.field(field.name) {
                    let _ = write!(rendered, " {}={}", field.name, field_value_text(&value));
                }
            }
            rendered
        }))?;
    }
    for diagnostic in &decoded.diagnostics {
        write_stdout_line(format_args!(
            "  {:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

/// Builds the protocol path plus the innermost addressed endpoints.
///
/// Endpoints are discovered reflectively rather than by protocol name, so a
/// tunnelled stack reports its innermost addressed layer and an external codec
/// that names its fields `source`/`destination` participates without changes.
fn frame_summary(decoded: &packet::decode::Result) -> String {
    let mut path = String::new();
    let mut endpoints: Option<(String, String)> = None;
    let mut ports: Option<(u64, u64)> = None;
    for layer in decoded.packet.iter() {
        if !path.is_empty() {
            path.push('/');
        }
        let _ = write!(path, "{}", layer.protocol_id());
        if let (Some(source), Some(destination)) =
            (layer.field("source"), layer.field("destination"))
            && let (Some(source), Some(destination)) =
                (address_text(&source), address_text(&destination))
        {
            endpoints = Some((source, destination));
            // A new addressed layer supersedes the ports of the layer above it.
            ports = None;
        }
        if let (Some(source), Some(destination)) = (
            layer.field("source_port").and_then(|value| value.as_u64()),
            layer
                .field("destination_port")
                .and_then(|value| value.as_u64()),
        ) {
            ports = Some((source, destination));
        }
    }

    let mut summary = path;
    if let Some((source, destination)) = endpoints {
        match ports {
            Some((source_port, destination_port)) => {
                let _ = write!(
                    summary,
                    " {source}:{source_port} > {destination}:{destination_port}"
                );
            }
            None => {
                let _ = write!(summary, " {source} > {destination}");
            }
        }
    }
    let diagnostics = decoded.diagnostics.len();
    if diagnostics != 0 {
        let _ = write!(summary, " diagnostics={diagnostics}");
    }
    summary
}

/// Renders an addressed field value, or `None` when the field is not an address.
fn address_text(value: &packet::field::FieldValue) -> Option<String> {
    match value {
        packet::field::FieldValue::Ipv4(address) => Some(address.to_string()),
        // Bracketed so the `:port` suffix stays unambiguous.
        packet::field::FieldValue::Ipv6(address) => Some(format!("[{address}]")),
        packet::field::FieldValue::Mac(address) => Some(mac_text(address)),
        packet::field::FieldValue::Bool(_)
        | packet::field::FieldValue::Unsigned(_)
        | packet::field::FieldValue::Signed(_)
        | packet::field::FieldValue::Text(_)
        | packet::field::FieldValue::Bytes(_)
        | packet::field::FieldValue::List(_) => None,
        _ => None,
    }
}

fn mac_text(address: &[u8; 6]) -> String {
    let mut rendered = String::with_capacity(17);
    for (index, byte) in address.iter().enumerate() {
        if index != 0 {
            rendered.push(':');
        }
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

fn field_value_text(value: &packet::field::FieldValue) -> String {
    match value {
        packet::field::FieldValue::Bool(value) => value.to_string(),
        packet::field::FieldValue::Unsigned(value) => value.to_string(),
        packet::field::FieldValue::Signed(value) => value.to_string(),
        packet::field::FieldValue::Text(value) => value.clone(),
        packet::field::FieldValue::Bytes(bytes) => spaced_hex(bytes),
        packet::field::FieldValue::Ipv4(address) => address.to_string(),
        packet::field::FieldValue::Ipv6(address) => address.to_string(),
        packet::field::FieldValue::Mac(address) => mac_text(address),
        packet::field::FieldValue::List(values) => {
            let mut rendered = String::from("[");
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    rendered.push(',');
                }
                rendered.push_str(&field_value_text(value));
            }
            rendered.push(']');
            rendered
        }
        // `FieldValue` is non-exhaustive so external codecs can grow the
        // vocabulary; render an unknown kind rather than refusing the frame.
        _ => "<unrepresentable>".to_owned(),
    }
}
