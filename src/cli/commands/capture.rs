// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Live capture and exchange commands.

fn cli_build_mode(mode: CliBuildMode) -> BuildMode {
    match mode {
        CliBuildMode::Strict => BuildMode::Strict,
        CliBuildMode::Permissive => BuildMode::Permissive,
    }
}

#[derive(Debug)]
struct CaptureOutcome {
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    stats: crate::output::envelope::Stats,
}

#[derive(Clone, Copy, Debug)]
struct CaptureBudget {
    max_frames: u64,
    max_bytes: u64,
}

impl From<&TrafficPolicy> for CaptureBudget {
    fn from(policy: &TrafficPolicy) -> Self {
        Self {
            max_frames: policy.max_packets_per_operation,
            max_bytes: policy.max_bytes_per_operation,
        }
    }
}

fn run_capture(arguments: CaptureArgs, output: OutputFormat) -> Result<(), CliError> {
    let CaptureArgs {
        route,
        timeout_ms,
        limits,
    } = arguments;
    let timeout = Duration::from_millis(timeout_ms);
    validate_capture_window(timeout)?;
    let limits = limits
        .into_limits()
        .validate()
        .map_err(CliError::classified)?;
    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, &registry)?;
    let budget = CaptureBudget::from(&request.policy);
    let client = system_client(Arc::clone(&registry), request.policy);
    let route = client
        .plan(&request.packet, request.destination, &request.options)
        .map_err(CliError::classified)?;

    match output {
        OutputFormat::Text => {
            let capture = SystemCaptureProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, sequence| {
                let frame = FrameOutput::try_from_frame(frame).map_err(CliError::classified)?;
                write_stdout_line(format_args!(
                    "{sequence}: dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))
            })?;
            write_stdout_line(format_args!(
                "captured {} frame(s), {} byte(s)",
                outcome.stats.packets_completed, outcome.stats.bytes
            ))?;
            render_diagnostics_text(&outcome.diagnostics)
        }
        OutputFormat::Hex => {
            let capture = SystemCaptureProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, _| {
                let frame = FrameOutput::try_from_frame(frame).map_err(CliError::classified)?;
                write_stdout_line(format_args!("{}", frame.bytes_hex))
            })?;
            render_diagnostics_stderr(&outcome.diagnostics)
        }
        OutputFormat::Ndjson => {
            let capture = SystemCaptureProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, sequence| {
                let frame = FrameOutput::try_from_frame(frame).map_err(CliError::classified)?;
                emit_json_compact(&StreamRecord::success(
                    CommandName::Capture,
                    sequence,
                    CaptureFrameCommandResult::Frame { frame },
                    Vec::new(),
                ))
                .map_err(|error| error.at_sequence(sequence))
            })?;
            let sequence = outcome.stats.packets_completed;
            emit_json_compact(
                &StreamRecord::success(
                    CommandName::Capture,
                    sequence,
                    CaptureFrameCommandResult::Complete { frames: sequence },
                    outcome.diagnostics,
                )
                .with_stats(outcome.stats),
            )
            .map_err(|error| error.at_sequence(sequence))
        }
        OutputFormat::Pcap | OutputFormat::Pcapng => {
            let format = capture_file_format(output)?;
            let mut capture = SystemCaptureProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let stdout = io::stdout();
            let mut writer = match Writer::with_limit(
                stdout.lock(),
                format,
                route.route.link_type,
                limits.snap_length,
            ) {
                Ok(writer) => writer,
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
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, _| {
                writer
                    .write_frame(&capture_file_frame(frame, format))
                    .map_err(|source| {
                        CliError::new(5, format!("write capture output failed: {source}"))
                    })
            })?;
            let mut stdout = writer.into_inner();
            stdout
                .flush()
                .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))?;
            render_diagnostics_stderr(&outcome.diagnostics)
        }
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Capture,
                format: output,
            },
        )),
    }
}

fn validate_capture_window(timeout: Duration) -> Result<(), CliError> {
    if timeout > crate::net::MAX_CAPTURE_TIMEOUT || Instant::now().checked_add(timeout).is_none() {
        return Err(CliError::classified(LiveIoError::InvalidCaptureTimeout {
            timeout,
            maximum: crate::net::MAX_CAPTURE_TIMEOUT,
        }));
    }
    Ok(())
}

fn drive_capture<C, F>(
    mut capture: C,
    timeout: Duration,
    limits: CaptureQueueLimits,
    budget: CaptureBudget,
    mut emit: F,
) -> Result<CaptureOutcome, CliError>
where
    C: CaptureSession,
    F: FnMut(Frame, u64) -> Result<(), CliError>,
{
    let started = Instant::now();
    let deadline = started
        .checked_add(timeout)
        .expect("validated capture timeout must fit the monotonic clock");
    if !timeout.is_zero() {
        let readiness_timeout = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if let Err(source) = capture.wait_ready(readiness_timeout) {
            let error = CliError::classified(source).at_sequence(0);
            return Err(shutdown_after_error(&mut capture, error));
        }
    }
    let mut frames = 0_u64;
    let mut bytes = 0_u64;
    while frames < budget.max_frames {
        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        let frame = match capture.next_frame(remaining) {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(source) => {
                let error = CliError::classified(source).at_sequence(frames);
                return Err(shutdown_after_error(&mut capture, error));
            }
        };
        let frame_bytes = u64::try_from(frame.bytes.len()).map_err(|_| {
            shutdown_after_error(
                &mut capture,
                CliError::new(70, "captured frame length exceeds the byte-accounting domain")
                    .at_sequence(frames),
            )
        })?;
        let next_bytes = bytes.checked_add(frame_bytes).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::new(70, "capture output byte accounting overflowed").at_sequence(frames),
            )
        })?;
        if next_bytes > budget.max_bytes {
            let error = CliError::classified(TrafficPolicyError::ByteLimit {
                actual: next_bytes,
                limit: budget.max_bytes,
            })
            .at_sequence(frames);
            return Err(shutdown_after_error(&mut capture, error));
        }
        bytes = next_bytes;
        if let Err(error) = emit(frame, frames) {
            return Err(shutdown_after_error(
                &mut capture,
                error.at_sequence_if_absent(frames),
            ));
        }
        frames = frames.checked_add(1).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::classified(OutputContractError::SequenceOverflow).at_sequence(frames),
            )
        })?;
    }
    capture
        .shutdown()
        .map_err(CliError::classified)
        .map_err(|error| error.at_sequence(frames))?;
    let statistics = capture
        .statistics()
        .validate()
        .map_err(CliError::classified)
        .map_err(|error| error.at_sequence(frames))?;
    let mut diagnostics = Vec::new();
    if statistics.has_loss() {
        if limits.overflow_policy == CaptureOverflowPolicy::Fail {
            return Err(CliError::classified(
                statistics
                    .evidence_loss_error()
                    .expect("lossy capture statistics must produce a typed error"),
            )
            .at_sequence(frames));
        }
        diagnostics.push(crate::packet::internal::Diagnostic::warning(
            "capture.evidence_incomplete",
            format!(
                "capture backend reported {} overflow event(s), {} receiver drop(s), {} total dropped frame(s), and {} dropped byte(s) under {:?}",
                statistics.overflow_events,
                statistics.receiver_dropped_frames,
                statistics.dropped_frames,
                statistics.dropped_bytes,
                limits.overflow_policy
            ),
        ));
    }
    Ok(CaptureOutcome {
        diagnostics,
        stats: crate::output::envelope::Stats {
            packets_attempted: frames,
            packets_completed: frames,
            bytes,
            elapsed: started.elapsed(),
            capture: statistics.into(),
        },
    })
}

fn shutdown_after_error<C: CaptureSession>(capture: &mut C, error: CliError) -> CliError {
    match capture.shutdown() {
        Ok(()) => error,
        Err(cleanup) => error.with_cleanup(cleanup),
    }
}

fn render_diagnostics_text(
    diagnostics: &[crate::packet::internal::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

fn render_output_diagnostics_text(
    diagnostics: &[crate::output::envelope::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

fn render_diagnostics_stderr(
    diagnostics: &[crate::packet::internal::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        emit_stderr_message(&format!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

fn run_exchange(arguments: ExchangeArgs, output: OutputFormat) -> Result<(), CliError> {
    let ExchangeArgs {
        send,
        timeout_ms,
        max_responses,
        max_unsolicited,
        limits,
    } = arguments;
    let SendArgs {
        route,
        mode,
        allow_permissive_live,
    } = send;
    let limits = limits.into_limits();
    let mut options = ExchangeOptions {
        timeout: Duration::from_millis(timeout_ms),
        max_template_packets: 1,
        max_responses,
        max_unsolicited,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        ..ExchangeOptions::default()
    };
    options.decode.max_packet_size = limits.snap_length;
    // Validate before packet parsing can trigger hostname/interface work.
    options.validate().map_err(CliError::classified)?;

    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, &registry)?;
    options.send = SendOptions {
        destination: request.destination,
        plan: request.options,
        build: BuildOptions {
            mode: cli_build_mode(mode),
            ..BuildOptions::default()
        },
        allow_permissive_live,
    };
    let client = system_client(Arc::clone(&registry), request.policy);
    let result = client
        .exchange(&PacketTemplate::new(request.packet), options)
        .map_err(CliError::classified)?;

    if matches!(output, OutputFormat::Pcap | OutputFormat::Pcapng) {
        let frames = result
            .sent_evidence
            .iter()
            .cloned()
            .chain(
                result
                    .responses
                    .iter()
                    .map(|response| response.response.frame.clone()),
            )
            .chain(result.unsolicited.iter().map(|packet| packet.frame.clone()))
            .chain(result.undecoded.iter().cloned())
            .collect::<Vec<_>>();
        let mut frames = frames;
        frames.sort_by_key(|frame| frame.timestamp);
        return write_capture_file(output, frames);
    }

    let (result, diagnostics, stats) =
        ExchangeCommandResult::try_from_exchange(result).map_err(CliError::classified)?;
    match output {
        OutputFormat::Text => {
            write_stdout_line(format_args!(
                "sent={} responses={} unanswered={} unsolicited={} undecoded={} bytes={}",
                result.sent.len(),
                result.responses.len(),
                result.unanswered.len(),
                result.unsolicited.len(),
                result.undecoded.len(),
                stats.bytes
            ))?;
            render_diagnostics_text(&diagnostics)
        }
        OutputFormat::Json => emit_json(
            &AggregateOutput::success(CommandName::Exchange, result, diagnostics).with_stats(stats),
        ),
        OutputFormat::Ndjson => render_exchange_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Exchange,
                format: output,
            },
        )),
    }
}

fn render_exchange_stream(
    result: ExchangeCommandResult,
    diagnostics: Vec<crate::packet::internal::Diagnostic>,
    stats: crate::output::envelope::Stats,
) -> Result<(), CliError> {
    let ExchangeCommandResult {
        sent,
        responses,
        unanswered,
        unsolicited,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    for (request_index, frame) in sent.into_iter().enumerate() {
        let request_index = u64::try_from(request_index)
            .map_err(|_| CliError::classified(OutputContractError::SequenceOverflow))?;
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Sent {
                request_index,
                frame,
            },
        )?;
    }
    for response in responses {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Response {
                request_index: response.request_index,
                response: response.response,
                latency: response.latency,
            },
        )?;
    }
    for request_index in &unanswered {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Unanswered {
                request_index: *request_index,
            },
        )?;
    }
    for frame in unsolicited {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Unsolicited { frame },
        )?;
    }
    for frame in undecoded {
        emit_exchange_record(
            &mut sequence,
            ExchangeStreamCommandResult::Undecoded { frame },
        )?;
    }
    emit_json_compact(
        &StreamRecord::success(
            CommandName::Exchange,
            sequence,
            ExchangeStreamCommandResult::Complete { unanswered },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

fn emit_exchange_record(
    sequence: &mut u64,
    result: ExchangeStreamCommandResult,
) -> Result<(), CliError> {
    emit_json_compact(&StreamRecord::success(
        CommandName::Exchange,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(OutputContractError::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}
