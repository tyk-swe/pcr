// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture CLI command logic.

pub(super) mod arguments;
mod conversion;
mod execution;
mod rendering;

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{
    analysis::pcap::{self as capture, Limits, PcapNgOptions, PcapOptions, Writer},
    network as net,
    network::capture::Provider as _,
    output,
};

use self::arguments::CaptureArgs;
use crate::capture_output::CaptureOutput;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities, FrameSelector};
use crate::rendering::{
    capture_file_format, captured_frame_text, emit_stream, emit_stream_with_stats,
    render_diagnostics_text, write_plain_line, write_stdout_line,
};
use crate::system::{default_registry_arc, prepare_route_request, system_client};

use conversion::validate_capture_window;
use execution::{CaptureBudget, drive_capture, shutdown_after_error};
use rendering::render_diagnostics_stderr;

pub(super) fn run(
    arguments: CaptureArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let CaptureArgs {
        route,
        timeout_ms,
        capture_filter,
        filter,
        limits,
        policy,
    } = arguments;
    let timeout = Duration::from_millis(timeout_ms);
    validate_capture_window(timeout)?;
    let limits = limits
        .into_limits()
        .validate()
        .map_err(CliError::classified)?;
    let registry = default_registry_arc()?;
    // Compile the display filter before live work; it affects reporting only and
    // uses the capture snapshot bound.
    let selector = match filter.as_deref() {
        Some(source) => {
            let filter = filtering::compile(source, &registry, Capabilities::frames_only())?;
            Some(FrameSelector::new(
                Arc::clone(&registry),
                filter,
                limits.snap_length,
            ))
        }
        None => None,
    };
    let request = prepare_route_request(route, policy.into_policy(), &registry)?;
    let budget = CaptureBudget::from(&request.policy);
    let client = system_client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(CliError::classified)?;
    let arm_capture = || match capture_filter.as_deref() {
        Some(filter) => {
            net::capture::SystemProvider.arm_capture_with_filter(&route, limits, filter)
        }
        None => net::capture::SystemProvider.arm_capture(&route, limits),
    };

    match output {
        output::contract::Format::Text => {
            let capture = arm_capture().map_err(CliError::classified)?;
            let outcome = drive_capture(
                capture,
                timeout,
                limits,
                budget,
                selector.as_ref(),
                |frame, sequence| {
                    let frame = output::capture::Frame::try_from_frame(frame)
                        .map_err(CliError::classified)?;
                    write_stdout_line(format_args!("{sequence}: {}", captured_frame_text(&frame)))
                },
            )?;
            match &selector {
                None => write_stdout_line(format_args!(
                    "captured {} frame(s), {} byte(s)",
                    outcome.stats.packets_completed, outcome.stats.bytes
                ))?,
                Some(_) => write_stdout_line(format_args!(
                    "matched {} of {} captured frame(s), {} byte(s)",
                    outcome.stats.packets_completed,
                    outcome.stats.packets_attempted,
                    outcome.stats.bytes
                ))?,
            }
            render_diagnostics_text(&outcome.diagnostics)
        }
        output::contract::Format::Hex => {
            let capture = arm_capture().map_err(CliError::classified)?;
            let outcome = drive_capture(
                capture,
                timeout,
                limits,
                budget,
                selector.as_ref(),
                |frame, _| {
                    let frame = output::capture::Frame::try_from_frame(frame)
                        .map_err(CliError::classified)?;
                    write_plain_line(format_args!("{}", frame.bytes_hex))
                },
            )?;
            render_diagnostics_stderr(&outcome.diagnostics)
        }
        output::contract::Format::Ndjson => {
            let capture = arm_capture().map_err(CliError::classified)?;
            let outcome = drive_capture(
                capture,
                timeout,
                limits,
                budget,
                selector.as_ref(),
                |frame, sequence| {
                    let frame = output::capture::Frame::try_from_frame(frame)
                        .map_err(CliError::classified)?;
                    emit_stream(
                        output::contract::Command::Capture,
                        sequence,
                        output::capture::Event::Frame { frame },
                        Vec::new(),
                    )
                },
            )?;
            let sequence = outcome.stats.packets_completed;
            emit_stream_with_stats(
                output::contract::Command::Capture,
                sequence,
                output::capture::Event::Complete { frames: sequence },
                outcome.diagnostics,
                outcome.stats,
            )
        }
        output::contract::Format::Pcap | output::contract::Format::Pcapng => {
            let format = capture_file_format(output)?;
            let configuration_error = match format {
                capture::Format::PcapNg if limits.snap_length < 32 => {
                    Some(capture::Error::SizeLimitExceeded {
                        kind: "pcapng interface description",
                        declared: 32,
                        limit: limits.snap_length,
                    })
                }
                capture::Format::PcapNg if route.route.link_type.0 > u16::MAX as u32 => {
                    Some(capture::Error::LinkTypeOutOfRange {
                        link_type: route.route.link_type.0,
                    })
                }
                _ => None,
            };
            if let Some(source) = configuration_error {
                return Err(CliError::new(
                    5,
                    format!("initialize capture output failed: {source}"),
                ));
            }
            let mut capture = arm_capture().map_err(CliError::classified)?;
            let stdout = io::stdout();
            let writer = match format {
                capture::Format::Pcap => Writer::pcap_with_options(
                    stdout.lock(),
                    route.route.link_type,
                    PcapOptions {
                        snap_len: limits.snap_length,
                        max_size: limits.snap_length,
                        ..PcapOptions::default()
                    },
                ),
                capture::Format::PcapNg => Writer::pcapng_with_options(
                    stdout.lock(),
                    PcapNgOptions {
                        max_size: limits.snap_length,
                        ..PcapNgOptions::default()
                    },
                ),
            };
            let mut writer = match writer.map(CaptureOutput::link_mapped) {
                Ok(mut writer) => {
                    if let Err(source) = writer.add_link_type(route.route.link_type) {
                        let error =
                            CliError::new(5, format!("initialize capture output failed: {source}"));
                        return Err(shutdown_after_error(&mut capture, error));
                    }
                    writer
                }
                Err(source) => {
                    let error =
                        CliError::new(5, format!("initialize capture output failed: {source}"));
                    return Err(shutdown_after_error(&mut capture, error));
                }
            };
            if let Err(source) = writer.set_stream_limits(Limits {
                max_frames: budget.max_frames,
                max_bytes: budget.max_bytes,
            }) {
                let error = CliError::classified(source);
                return Err(shutdown_after_error(&mut capture, error));
            }
            let outcome = drive_capture(
                capture,
                timeout,
                limits,
                budget,
                selector.as_ref(),
                |frame, _| {
                    writer
                        .write_on_link_type(route.route.link_type, frame)
                        .map_err(|source| {
                            CliError::new(5, format!("write capture output failed: {source}"))
                        })
                },
            )?;
            let mut stdout = writer.into_inner();
            stdout
                .flush()
                .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))?;
            render_diagnostics_stderr(&outcome.diagnostics)
        }
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Capture,
                format: output,
            },
        )),
    }
}
