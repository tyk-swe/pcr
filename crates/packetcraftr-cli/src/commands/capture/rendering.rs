// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
use std::time::Duration;

use packetcraftr::{
    analysis::pcap::{self as capture, Limits, PcapNgOptions, PcapOptions, Writer},
    core::{self, frame::LinkType},
    netio as net, output,
};

use super::execution::{self, Budget, shutdown_after_error};
use crate::errors::CliError;
use crate::filtering::FrameSelector;
use crate::rendering::{
    CaptureWriter, capture_file_format, captured_frame_text, emit, emit_stderr_message,
    emit_with_stats, render_diagnostics_text, write_plain_line, write_stdout_line,
};

pub(super) fn render_text<C: net::capture::Session>(
    capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: Budget,
    selector: Option<&FrameSelector>,
) -> Result<(), CliError> {
    let outcome = execution::run(
        capture,
        timeout,
        limits,
        budget,
        selector,
        |frame, sequence| {
            let frame =
                output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
            write_stdout_line(format_args!("{sequence}: {}", captured_frame_text(&frame)))
        },
    )?;
    if selector.is_some() {
        write_stdout_line(format_args!(
            "matched {} of {} captured frame(s), {} byte(s)",
            outcome.stats.packets_completed, outcome.stats.packets_attempted, outcome.stats.bytes
        ))?;
    } else {
        write_stdout_line(format_args!(
            "captured {} frame(s), {} byte(s)",
            outcome.stats.packets_completed, outcome.stats.bytes
        ))?;
    }
    render_diagnostics_text(&outcome.diagnostics)
}

pub(super) fn render_hex<C: net::capture::Session>(
    capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: Budget,
    selector: Option<&FrameSelector>,
) -> Result<(), CliError> {
    let outcome = execution::run(capture, timeout, limits, budget, selector, |frame, _| {
        let frame = output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
        write_plain_line(format_args!("{}", frame.bytes_hex()))
    })?;
    render_diagnostics(&outcome.diagnostics)
}

pub(super) fn render_stream<C: net::capture::Session>(
    capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: Budget,
    selector: Option<&FrameSelector>,
) -> Result<(), CliError> {
    let outcome = execution::run(
        capture,
        timeout,
        limits,
        budget,
        selector,
        |frame, sequence| {
            let frame =
                output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
            emit(
                output::contract::Command::Capture,
                sequence,
                output::capture::Event::Frame { frame },
                Vec::new(),
            )
        },
    )?;
    let sequence = outcome.stats.packets_completed;
    emit_with_stats(
        output::contract::Command::Capture,
        sequence,
        output::capture::Event::Complete { frames: sequence },
        outcome.diagnostics,
        outcome.stats,
    )
}

pub(super) fn render_capture<A>(
    arm_capture: A,
    format: output::contract::Format,
    link_type: LinkType,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: Budget,
    selector: Option<&FrameSelector>,
) -> Result<(), CliError>
where
    A: FnOnce() -> Result<net::capture::SystemSession, net::Error>,
{
    let format = capture_file_format(format)?;
    validate_writer_configuration(format, link_type, limits.snap_length)?;
    let mut capture = arm_capture().map_err(CliError::classified)?;
    let stdout = io::stdout();
    let mut writer =
        match initialize_writer(stdout.lock(), format, link_type, limits.snap_length, budget) {
            Ok(writer) => writer,
            Err(error) => return Err(shutdown_after_error(&mut capture, error)),
        };
    let outcome = execution::run(capture, timeout, limits, budget, selector, |frame, _| {
        writer
            .write_on_link_type(link_type, frame)
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))
    })?;
    writer
        .into_inner()
        .flush()
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))?;
    render_diagnostics(&outcome.diagnostics)
}

fn validate_writer_configuration(
    format: capture::Format,
    link_type: LinkType,
    max_size: usize,
) -> Result<(), CliError> {
    let error = match format {
        capture::Format::PcapNg if max_size < 32 => Some(capture::Error::SizeLimitExceeded {
            kind: "pcapng interface description",
            declared: 32,
            limit: max_size,
        }),
        capture::Format::PcapNg if link_type.0 > u32::from(u16::MAX) => {
            Some(capture::Error::LinkTypeOutOfRange {
                link_type: link_type.0,
            })
        }
        _ => None,
    };
    match error {
        Some(source) => Err(CliError::new(
            5,
            format!("initialize capture output failed: {source}"),
        )),
        None => Ok(()),
    }
}

fn initialize_writer<W: Write>(
    destination: W,
    format: capture::Format,
    link_type: LinkType,
    max_size: usize,
    budget: Budget,
) -> Result<CaptureWriter<W>, CliError> {
    let writer = match format {
        capture::Format::Pcap => Writer::pcap_with_options(
            destination,
            link_type,
            PcapOptions {
                snap_len: max_size,
                max_size,
                ..PcapOptions::default()
            },
        ),
        capture::Format::PcapNg => Writer::pcapng_with_options(
            destination,
            PcapNgOptions {
                max_size,
                ..PcapNgOptions::default()
            },
        ),
    }
    .map_err(|source| CliError::new(5, format!("initialize capture output failed: {source}")))?;
    let mut writer = CaptureWriter::for_link_types(writer);
    writer.add_link_type(link_type).map_err(|source| {
        CliError::new(5, format!("initialize capture output failed: {source}"))
    })?;
    writer
        .set_stream_limits(Limits {
            max_frames: budget.max_frames,
            max_bytes: budget.max_bytes,
        })
        .map_err(CliError::classified)?;
    Ok(writer)
}

fn render_diagnostics(diagnostics: &[core::diagnostic::Diagnostic]) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        emit_stderr_message(&format!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}
