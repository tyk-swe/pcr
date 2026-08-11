// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Replay CLI command logic.

pub(super) mod arguments;
mod conversion;
mod execution;
mod rendering;

use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr::{
    analysis::pcap::{Reader, ReaderOptions},
    output,
};

use self::arguments::ReplayArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities, FrameSelector};
use crate::input::validate_capture_stream_limits;
use crate::rendering::{
    capture_file_format, emit_aggregate_with_stats, emit_stream_with_stats, write_stdout_line,
};
use crate::system::default_registry_arc;

use conversion::{replay_timing, requested_replay_interface};
use execution::{DisplayFilterSelector, execute_replay};
use rendering::{
    emit_replay_ndjson_evidence, replay_capture_output, replay_output_frame, replay_stats,
    write_replay_capture_evidence, write_replay_text_evidence,
};

pub(super) fn run(arguments: ReplayArgs, output: output::contract::Format) -> Result<(), CliError> {
    let policy = arguments.policy.clone().into_policy();
    validate_capture_stream_limits(
        policy.max_packets_per_operation,
        policy.max_bytes_per_operation,
        arguments.max_frame_bytes,
        arguments.max_interfaces,
    )?;
    let timing = replay_timing(&arguments)?;
    let registry = default_registry_arc()?;
    // The filter compiles with the other argument validation, before the
    // capture is opened and long before any authorization or transmission.
    let frame_filter = match arguments.filter.as_deref() {
        Some(source) => {
            let filter = filtering::compile(source, &registry, Capabilities::frames_only())?;
            Some(FrameSelector::new(
                Arc::clone(&registry),
                filter,
                arguments.max_frame_bytes,
            ))
        }
        None => None,
    };
    let requested_interface = requested_replay_interface(&arguments.interface)?;
    policy.validate().map_err(CliError::classified)?;
    let limits = packetcraftr::replay::Limits {
        max_frames: policy.max_packets_per_operation,
        max_bytes: policy.max_bytes_per_operation,
        max_frame_bytes: arguments.max_frame_bytes,
        max_duration: Duration::from_millis(arguments.max_duration_ms),
    }
    .validate()
    .map_err(CliError::classified)?;
    let file = File::open(&arguments.path).map_err(|source| {
        CliError::new(
            5,
            format!("open {} failed: {source}", arguments.path.display()),
        )
    })?;
    let mut reader = Reader::with_options(
        file,
        ReaderOptions {
            max_size: arguments.max_frame_bytes,
            max_interfaces_per_section: arguments.max_interfaces,
            ..ReaderOptions::default()
        },
    )
    .map_err(CliError::classified)?;
    let mut authorizer =
        packetcraftr::replay::SystemAuthorizer::new(policy, arguments.allow_malformed_live);
    let options = packetcraftr::replay::Options {
        interface: requested_interface.clone(),
        link_mode: arguments.link_mode.into(),
        timing,
        limits,
    };
    let mut adapter = frame_filter
        .as_ref()
        .map(|selector| DisplayFilterSelector { selector });
    let selector = adapter
        .as_mut()
        .map(|adapter| adapter as &mut dyn packetcraftr::replay::Selector);
    let mut transmitter = packetcraftr::replay::SystemTransmitter::new();
    let mut clock = packetcraftr::clock::SystemClock;
    let started = Instant::now();

    match output {
        output::contract::Format::Text => {
            let summary = execute_replay(
                &mut reader,
                &options,
                selector,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                write_replay_text_evidence,
            )?;
            match &frame_filter {
                None => write_stdout_line(format_args!(
                    "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
                    summary.frames_completed, summary.bytes_completed, summary.scheduled_duration
                )),
                Some(_) => write_stdout_line(format_args!(
                    "replayed {} of {} frame(s), {} byte(s), scheduled delay {:?}",
                    summary.frames_completed,
                    summary.frames_attempted,
                    summary.bytes_completed,
                    summary.scheduled_duration
                )),
            }
        }
        output::contract::Format::Json => {
            let mut frames = Vec::new();
            let summary = execute_replay(
                &mut reader,
                &options,
                selector,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| {
                    frames.push(replay_output_frame(evidence)?);
                    Ok(())
                },
            )?;
            let stats = replay_stats(&summary, started.elapsed());
            let result = output::replay::Result::from_summary(
                summary,
                requested_interface,
                options.link_mode,
                frames,
            );
            emit_aggregate_with_stats(output::contract::Command::Replay, result, Vec::new(), stats)
        }
        output::contract::Format::Ndjson => {
            let mut sequence = 0_u64;
            let summary = execute_replay(
                &mut reader,
                &options,
                selector,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| emit_replay_ndjson_evidence(&mut sequence, evidence),
            )?;
            let stats = replay_stats(&summary, started.elapsed());
            let result = output::replay::Result::from_summary(
                summary,
                requested_interface,
                options.link_mode,
                Vec::new(),
            );
            emit_stream_with_stats(
                output::contract::Command::Replay,
                sequence,
                result,
                Vec::new(),
                stats,
            )
        }
        output::contract::Format::Pcap | output::contract::Format::Pcapng => {
            let format = capture_file_format(output)?;
            let stdout = io::stdout();
            let mut writer = replay_capture_output(
                &reader,
                stdout.lock(),
                format,
                limits,
                arguments.max_interfaces,
            )?;
            execute_replay(
                &mut reader,
                &options,
                selector,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |evidence| write_replay_capture_evidence(&mut writer, evidence),
            )?;
            writer.flush().map_err(CliError::classified)
        }
        _ => unreachable!("replay format is checked before command dispatch"),
    }
}

pub(crate) fn replay_cli_error(error: packetcraftr::replay::Error) -> CliError {
    let sequence = error.sequence();
    CliError::classified_at_optional_sequence(error, sequence)
}
