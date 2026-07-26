// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Batch and live frame dissection.

use std::fmt::Write as _;
use std::time::Duration;

use packetcraftr::net::capture::Provider as _;
use packetcraftr::{
    capture::{self, Frame},
    net, output, packet,
};

use super::super::arguments::{CaptureStreamLimitArgs, DecodeArgs};
use super::super::errors::CliError;
use super::super::rendering::{
    emit_json, emit_json_compact, output_timestamp_text, spaced_hex, write_stdout_line,
};
use super::super::runtime::{default_registry_arc, observe_interface_route};
use super::capture::{
    CaptureBudget, drive_capture, render_diagnostics_text, validate_capture_window,
};
use super::offline::{open_capture_reader, validate_capture_stream_limits};

pub(crate) fn run_decode(
    arguments: DecodeArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let DecodeArgs {
        path,
        interface,
        filter,
        verbose,
        timeout_ms,
        no_promiscuous,
        limits:
            CaptureStreamLimitArgs {
                max_frames,
                max_bytes,
                max_frame_bytes,
                max_interfaces,
            },
        capture_limits,
    } = arguments;
    validate_capture_stream_limits(max_frames, max_bytes, max_frame_bytes, max_interfaces)?;
    let registry = default_registry_arc()?;
    // Compiled before any input is opened so a mistyped filter fails without
    // reading a capture file or arming an interface.
    let filter = compile_filter(filter.as_deref(), &registry)?;
    let decoder = packet::decode::Decoder::new(registry);
    let decode_options = packet::decode::Options {
        max_packet_size: max_frame_bytes,
        ..packet::decode::Options::default()
    };
    if let Some(selector) = interface {
        return run_live_decode(
            LiveDecode {
                selector,
                filter,
                verbose,
                timeout: Duration::from_millis(timeout_ms),
                no_promiscuous,
                budget: CaptureBudget {
                    max_frames,
                    max_bytes,
                },
                limits: capture_limits.into_limits(),
            },
            decoder,
            decode_options,
            output,
        );
    }
    let path = path.expect("clap requires a path when no interface is selected");
    let mut reader = open_capture_reader(&path, max_frame_bytes, max_interfaces)?;

    // `source_index` identifies a frame within the input, so a text line keeps
    // naming the same frame `read` would. `emitted` is the envelope record
    // sequence, which stays contiguous even when a filter skips frames.
    let mut source_index = 0_u64;
    let mut emitted = 0_u64;
    let mut emitted_bytes = 0_u64;
    let mut filtered = 0_u64;
    let mut captured_bytes = 0_u64;
    let mut aggregate = Vec::new();
    loop {
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| CliError::classified(source).at_sequence(emitted))?
        else {
            break;
        };
        let next_index = source_index.checked_add(1).ok_or_else(|| {
            CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(emitted)
        })?;
        if next_index > max_frames {
            return Err(CliError::classified(capture::Error::FrameLimitExceeded {
                actual: next_index,
                limit: max_frames,
            })
            .at_sequence(emitted));
        }
        captured_bytes = next_captured_bytes(captured_bytes, &frame, max_bytes, emitted)?;

        let decoded = decoder
            .decode(frame, decode_options.clone())
            .map_err(|source| CliError::new(3, source.to_string()).at_sequence(emitted))?;
        if filter
            .as_ref()
            .is_some_and(|filter| !filter.matches(&decoded.packet))
        {
            filtered += 1;
            source_index = next_index;
            continue;
        }
        emitted_bytes += u64::from(decoded.frame.captured_length());
        match output {
            output::contract::Format::Text => {
                render_decoded_text(source_index, &decoded, verbose)?;
            }
            output::contract::Format::Ndjson => {
                let decoded = decoded_output(decoded, emitted)?;
                emit_json_compact(&output::envelope::Stream::success(
                    output::contract::Command::Decode,
                    emitted,
                    output::decode::Event::Frame { decoded },
                    Vec::new(),
                ))
                .map_err(|error| error.at_sequence(emitted))?;
            }
            output::contract::Format::Json => aggregate.push(decoded_output(decoded, emitted)?),
            _ => {
                return Err(CliError::classified(
                    output::contract::Error::UnsupportedFormat {
                        command: output::contract::Command::Decode,
                        format: output,
                    },
                ));
            }
        }
        source_index = next_index;
        emitted += 1;
    }

    match output {
        output::contract::Format::Text => write_stdout_line(format_args!(
            "decoded {emitted} frame(s), {emitted_bytes} byte(s){}",
            filtered_suffix(filtered)
        )),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Decode,
            output::decode::Result {
                frames: aggregate,
                count: emitted,
                filtered,
            },
            Vec::new(),
        )),
        output::contract::Format::Ndjson => emit_json_compact(&output::envelope::Stream::success(
            output::contract::Command::Decode,
            emitted,
            output::decode::Event::Complete {
                frames: emitted,
                filtered,
            },
            Vec::new(),
        ))
        .map_err(|error| error.at_sequence(emitted)),
        _ => unreachable!("unsupported formats are rejected inside the frame loop"),
    }
}

/// Compiles a display filter before any capture source is opened.
fn compile_filter(
    source: Option<&str>,
    registry: &packet::registry::Registry,
) -> Result<Option<packet::filter::Filter>, CliError> {
    source
        .map(|source| {
            packet::filter::Filter::compile(source, registry, packet::filter::Options::default())
                .map_err(|error| CliError::new(2, error.to_string()))
        })
        .transpose()
}

fn filtered_suffix(filtered: u64) -> String {
    if filtered == 0 {
        return String::new();
    }
    format!(", {filtered} filtered out")
}

struct LiveDecode {
    selector: String,
    filter: Option<packet::filter::Filter>,
    verbose: bool,
    timeout: Duration,
    no_promiscuous: bool,
    budget: CaptureBudget,
    limits: net::capture::Limits,
}

/// Dissects frames as they are captured from one interface.
///
/// Live decoding shares the capture drive loop with `capture`, so the same
/// readiness barrier, budgets, shutdown, and loss accounting apply; only the
/// per-frame rendering differs. The aggregate JSON result is deliberately
/// offline-only: it would have to buffer an unbounded live stream before
/// emitting anything.
fn run_live_decode(
    arguments: LiveDecode,
    decoder: packet::decode::Decoder,
    decode_options: packet::decode::Options,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let LiveDecode {
        selector,
        filter,
        verbose,
        timeout,
        no_promiscuous,
        budget,
        limits,
    } = arguments;
    if matches!(output, output::contract::Format::Json) {
        return Err(CliError::new(
            2,
            "decode --interface streams frames as they arrive; use text or ndjson output",
        ));
    }
    validate_capture_window(timeout)?;
    let limits = limits.validate().map_err(CliError::classified)?;
    let route = observe_interface_route(selector)?;
    let capture = net::capture::SystemProvider
        .arm_capture_with(
            &route,
            net::capture::Options {
                limits,
                promiscuous: if no_promiscuous {
                    net::capture::Promiscuous::Disabled
                } else {
                    net::capture::Promiscuous::Enabled
                },
            },
        )
        .map_err(CliError::classified)?;

    let mut emitted = 0_u64;
    let mut emitted_bytes = 0_u64;
    let mut filtered = 0_u64;
    let outcome = drive_capture(capture, timeout, limits, budget, |frame, source_index| {
        let decoded = decoder
            .decode(frame, decode_options.clone())
            .map_err(|source| CliError::new(3, source.to_string()).at_sequence(emitted))?;
        if filter
            .as_ref()
            .is_some_and(|filter| !filter.matches(&decoded.packet))
        {
            filtered += 1;
            return Ok(());
        }
        emitted_bytes += u64::from(decoded.frame.captured_length());
        let result = match output {
            output::contract::Format::Text => render_decoded_text(source_index, &decoded, verbose),
            output::contract::Format::Ndjson => {
                let decoded = decoded_output(decoded, emitted)?;
                emit_json_compact(&output::envelope::Stream::success(
                    output::contract::Command::Decode,
                    emitted,
                    output::decode::Event::Frame { decoded },
                    Vec::new(),
                ))
                .map_err(|error| error.at_sequence(emitted))
            }
            _ => Err(CliError::classified(
                output::contract::Error::UnsupportedFormat {
                    command: output::contract::Command::Decode,
                    format: output,
                },
            )),
        };
        result.inspect(|()| emitted += 1)
    })?;

    match output {
        output::contract::Format::Text => {
            write_stdout_line(format_args!(
                "decoded {emitted} frame(s), {emitted_bytes} byte(s){}",
                filtered_suffix(filtered)
            ))?;
            render_diagnostics_text(&outcome.diagnostics)
        }
        output::contract::Format::Ndjson => emit_json_compact(
            &output::envelope::Stream::success(
                output::contract::Command::Decode,
                emitted,
                output::decode::Event::Complete {
                    frames: emitted,
                    filtered,
                },
                outcome.diagnostics,
            )
            .with_stats(outcome.stats),
        )
        .map_err(|error| error.at_sequence(emitted)),
        _ => unreachable!("unsupported formats are rejected before the capture is armed"),
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
pub(crate) fn frame_summary(decoded: &packet::decode::Result) -> String {
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
