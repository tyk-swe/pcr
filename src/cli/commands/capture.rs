// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Live capture and exchange commands.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr::net::capture::Provider as _;
use packetcraftr::{
    capture::{Frame, Limits, Writer},
    client, net, output, packet,
};

use super::arguments::{CaptureArgs, CliBuildMode, ExchangeArgs, SendArgs};
use super::errors::CliError;
use super::rendering::{
    NdjsonStream, capture_file_format, capture_file_frame, emit_json, emit_json_compact,
    emit_stderr_message, spaced_hex, write_capture_file, write_stdout_line,
};
use super::runtime::{default_registry_arc, prepare_route_request, system_client};

pub(super) fn cli_build_mode(mode: CliBuildMode) -> packet::build::Mode {
    match mode {
        CliBuildMode::Strict => packet::build::Mode::Strict,
        CliBuildMode::Permissive => packet::build::Mode::Permissive,
    }
}

#[derive(Debug)]
pub(super) struct CaptureOutcome {
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    pub(super) stats: output::envelope::Stats,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct CaptureBudget {
    pub(super) max_frames: u64,
    pub(super) max_bytes: u64,
}

impl From<&client::policy::Policy> for CaptureBudget {
    fn from(policy: &client::policy::Policy) -> Self {
        Self {
            max_frames: policy.max_packets_per_operation,
            max_bytes: policy.max_bytes_per_operation,
        }
    }
}

pub(super) fn run_capture(
    arguments: CaptureArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
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
        output::contract::Format::Text => {
            let capture = net::capture::SystemProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, sequence| {
                let frame =
                    output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
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
        output::contract::Format::Hex => {
            let capture = net::capture::SystemProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, _| {
                let frame =
                    output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
                write_stdout_line(format_args!("{}", frame.bytes_hex))
            })?;
            render_diagnostics_stderr(&outcome.diagnostics)
        }
        output::contract::Format::Ndjson => {
            let capture = net::capture::SystemProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(capture, timeout, limits, budget, |frame, sequence| {
                let frame =
                    output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
                emit_json_compact(&output::envelope::Stream::success(
                    output::contract::Command::Capture,
                    sequence,
                    output::capture::Event::Frame { frame },
                    Vec::new(),
                ))
                .map_err(|error| error.at_sequence(sequence))
            })?;
            let sequence = outcome.stats.packets_completed;
            emit_json_compact(
                &output::envelope::Stream::success(
                    output::contract::Command::Capture,
                    sequence,
                    output::capture::Event::Complete { frames: sequence },
                    outcome.diagnostics,
                )
                .with_stats(outcome.stats),
            )
            .map_err(|error| error.at_sequence(sequence))
        }
        output::contract::Format::Pcap | output::contract::Format::Pcapng => {
            let format = capture_file_format(output)?;
            let mut capture = net::capture::SystemProvider
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
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Capture,
                format: output,
            },
        )),
    }
}

fn validate_capture_window(timeout: Duration) -> Result<(), CliError> {
    if timeout > net::capture::MAX_TIMEOUT || Instant::now().checked_add(timeout).is_none() {
        return Err(CliError::classified(net::Error::InvalidCaptureTimeout {
            timeout,
            maximum: net::capture::MAX_TIMEOUT,
        }));
    }
    Ok(())
}

pub(super) fn drive_capture<C, F>(
    mut capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: CaptureBudget,
    mut emit: F,
) -> Result<CaptureOutcome, CliError>
where
    C: net::capture::Session,
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
        let frame_bytes = u64::try_from(frame.bytes().len()).map_err(|_| {
            shutdown_after_error(
                &mut capture,
                CliError::new(
                    70,
                    "captured frame length exceeds the byte-accounting domain",
                )
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
            let error = CliError::classified(client::policy::Error::ByteLimit {
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
                CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(frames),
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
        if limits.overflow_policy == net::capture::OverflowPolicy::Fail {
            return Err(CliError::classified(
                statistics
                    .evidence_loss_error()
                    .expect("lossy capture statistics must produce a typed error"),
            )
            .at_sequence(frames));
        }
        diagnostics.push(packet::diagnostic::Diagnostic::warning(
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
        stats: output::envelope::Stats {
            packets_attempted: frames,
            packets_completed: frames,
            bytes,
            elapsed: started.elapsed(),
            capture: statistics.into(),
        },
    })
}

fn shutdown_after_error<C: net::capture::Session>(capture: &mut C, error: CliError) -> CliError {
    match capture.shutdown() {
        Ok(()) => error,
        Err(cleanup) => error.with_cleanup(cleanup),
    }
}

pub(super) fn render_diagnostics_text(
    diagnostics: &[packet::diagnostic::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

pub(super) fn render_output_diagnostics_text(
    diagnostics: &[output::envelope::Diagnostic],
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
    diagnostics: &[packet::diagnostic::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        emit_stderr_message(&format!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

pub(super) fn run_exchange(
    arguments: ExchangeArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
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
    let mut options = client::exchange::Options {
        timeout: Duration::from_millis(timeout_ms),
        max_template_packets: 1,
        max_responses,
        max_unsolicited,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        ..client::exchange::Options::default()
    };
    options.decode.max_packet_size = limits.snap_length;
    // Validate before packet parsing can trigger hostname/interface work.
    options.validate().map_err(CliError::classified)?;

    let registry = default_registry_arc()?;
    let request = prepare_route_request(route, &registry)?;
    options.send = client::send::Options {
        destination: request.destination,
        plan: request.options,
        build: packet::build::Options {
            mode: cli_build_mode(mode),
            ..packet::build::Options::default()
        },
        allow_permissive_live,
    };
    let client = system_client(Arc::clone(&registry), request.policy);
    let template = packet::template::Template::new(request.packet);
    if output == output::contract::Format::Ndjson {
        let stdout = io::stdout();
        let mut stream = NdjsonStream::new(stdout.lock(), output::contract::Command::Exchange);
        let result = {
            let mut observer = ExchangeStreamObserver {
                stream: &mut stream,
            };
            client.exchange_observed(&template, options, &mut observer)
        };
        let result = match result {
            Ok(result) => result,
            Err(client::exchange::ObservedError::Operation(error)) => {
                let error = CliError::classified(error).at_sequence(stream.next_sequence());
                drop(stream);
                return Err(error);
            }
            Err(client::exchange::ObservedError::Observer(error)) => {
                drop(stream);
                return Err(error);
            }
            Err(client::exchange::ObservedError::ObserverAndCaptureShutdown {
                observer,
                shutdown,
            }) => {
                let error = observer.with_cleanup(shutdown);
                drop(stream);
                return Err(error);
            }
        };
        let client::exchange::Result {
            sent,
            sent_evidence: _,
            responses: _,
            unanswered,
            unsolicited: _,
            undecoded: _,
            mut diagnostics,
            stats,
        } = result;
        let unanswered = unanswered
            .into_iter()
            .map(|request_index| {
                u64::try_from(request_index).map_err(|_| {
                    CliError::classified(output::contract::Error::SequenceOverflow)
                        .at_sequence(stream.next_sequence())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for request_index in &unanswered {
            stream.emit(
                output::network::exchange::Event::Unanswered {
                    request_index: *request_index,
                },
                Vec::new(),
            )?;
        }
        for built in sent {
            diagnostics.extend(built.diagnostics);
        }
        return stream.emit_terminal(
            output::network::exchange::Event::Complete { unanswered },
            diagnostics,
            stats.into(),
        );
    }
    let result = client
        .exchange(&template, options)
        .map_err(CliError::classified)?;

    if matches!(
        output,
        output::contract::Format::Pcap | output::contract::Format::Pcapng
    ) {
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

    let (result, diagnostics, stats) = output::network::exchange::Result::try_from_exchange(result)
        .map_err(CliError::classified)?;
    match output {
        output::contract::Format::Text => {
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
        output::contract::Format::Json => emit_json(
            &output::envelope::Aggregate::success(
                output::contract::Command::Exchange,
                result,
                diagnostics,
            )
            .with_stats(stats),
        ),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Exchange,
                format: output,
            },
        )),
    }
}

struct ExchangeStreamObserver<'a, W: Write> {
    stream: &'a mut NdjsonStream<W>,
}

impl<W: Write> client::exchange::ProgressObserver for ExchangeStreamObserver<'_, W> {
    type Error = CliError;

    fn observe(&mut self, progress: client::exchange::Progress<'_>) -> Result<(), Self::Error> {
        let event = match progress {
            client::exchange::Progress::Sent {
                request_index,
                built,
                evidence: _,
            } => output::network::exchange::Event::Sent {
                request_index: u64::try_from(request_index).map_err(|_| {
                    CliError::classified(output::contract::Error::SequenceOverflow)
                        .at_sequence(self.stream.next_sequence())
                })?,
                frame: output::frame::Wire::new(built.bytes.clone()),
            },
            client::exchange::Progress::Response { response } => {
                output::network::exchange::Event::Response {
                    request_index: u64::try_from(response.request_index).map_err(|_| {
                        CliError::classified(output::contract::Error::SequenceOverflow)
                            .at_sequence(self.stream.next_sequence())
                    })?,
                    response: output::frame::Decoded::try_from_decoded_ref(&response.response)
                        .map_err(|error| {
                            CliError::classified(error).at_sequence(self.stream.next_sequence())
                        })?,
                    latency: response.latency,
                }
            }
            client::exchange::Progress::Unsolicited { response } => {
                output::network::exchange::Event::Unsolicited {
                    frame: output::frame::Decoded::try_from_decoded_ref(response).map_err(
                        |error| {
                            CliError::classified(error).at_sequence(self.stream.next_sequence())
                        },
                    )?,
                }
            }
            client::exchange::Progress::Undecoded { frame } => {
                output::network::exchange::Event::Undecoded {
                    frame: output::frame::Captured::try_from_frame_ref(frame).map_err(|error| {
                        CliError::classified(error).at_sequence(self.stream.next_sequence())
                    })?,
                }
            }
        };
        self.stream.emit(event, Vec::new())
    }
}
