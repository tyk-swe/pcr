// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Live capture and exchange commands.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr::net::capture::Provider as _;
use packetcraftr::{
    capture::{self, Frame, Limits, PcapNgOptions, PcapOptions, Writer},
    client, net, output, packet,
};

use super::super::arguments::{CaptureArgs, ExchangeArgs, SendArgs};
use super::super::capture_output::CaptureOutput;
use super::super::errors::CliError;
use super::super::filtering::{self, Capabilities, FrameSelector};
use super::super::rendering::{
    capture_file_format, emit_json, emit_json_compact, emit_stderr_message, emit_stream_record,
    render_diagnostics_text, spaced_hex, write_capture_file, write_plain_line, write_stdout_line,
};
use super::super::runtime::{default_registry_arc, prepare_route_request, system_client};

#[derive(Debug)]
pub(crate) struct CaptureOutcome {
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    pub(crate) stats: output::envelope::Stats,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CaptureBudget {
    pub(crate) max_frames: u64,
    pub(crate) max_bytes: u64,
}

impl From<&client::policy::Policy> for CaptureBudget {
    fn from(policy: &client::policy::Policy) -> Self {
        Self {
            max_frames: policy.max_packets_per_operation,
            max_bytes: policy.max_bytes_per_operation,
        }
    }
}

pub(crate) fn run_capture(
    arguments: CaptureArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let CaptureArgs {
        route,
        timeout_ms,
        filter,
        limits,
    } = arguments;
    let timeout = Duration::from_millis(timeout_ms);
    validate_capture_window(timeout)?;
    let limits = limits
        .into_limits()
        .validate()
        .map_err(CliError::classified)?;
    let registry = default_registry_arc()?;
    // The filter compiles before any route, resolution, or capture work, so a
    // mistyped expression is refused without live side effects. Received
    // frames are dissected under the same snapshot bound the capture reads
    // with; this selects what is reported, it does not narrow what the
    // backend captures.
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
            let outcome = drive_capture(
                capture,
                timeout,
                limits,
                budget,
                selector.as_ref(),
                |frame, sequence| {
                    let frame = output::frame::Captured::try_from_frame(frame)
                        .map_err(CliError::classified)?;
                    write_stdout_line(format_args!(
                        "{sequence}: dlt={} caplen={} wirelen={} {}",
                        frame.link_type,
                        frame.captured_length,
                        frame.original_length,
                        spaced_hex(frame.bytes())
                    ))
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
            let capture = net::capture::SystemProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(
                capture,
                timeout,
                limits,
                budget,
                selector.as_ref(),
                |frame, _| {
                    let frame = output::frame::Captured::try_from_frame(frame)
                        .map_err(CliError::classified)?;
                    write_plain_line(format_args!("{}", frame.bytes_hex))
                },
            )?;
            render_diagnostics_stderr(&outcome.diagnostics)
        }
        output::contract::Format::Ndjson => {
            let capture = net::capture::SystemProvider
                .arm_capture(&route, limits)
                .map_err(CliError::classified)?;
            let outcome = drive_capture(
                capture,
                timeout,
                limits,
                budget,
                selector.as_ref(),
                |frame, sequence| {
                    let frame = output::frame::Captured::try_from_frame(frame)
                        .map_err(CliError::classified)?;
                    emit_json_compact(&output::envelope::Stream::success(
                        output::contract::Command::Capture,
                        sequence,
                        output::capture::Event::Frame { frame },
                        Vec::new(),
                    ))
                    .map_err(|error| error.at_sequence(sequence))
                },
            )?;
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
                capture::Format::PcapNg => (|| {
                    // Reject mandatory-interface configuration before the
                    // section header is committed to stdout.
                    if limits.snap_length < 32 {
                        return Err(capture::Error::SizeLimitExceeded {
                            kind: "pcapng interface description",
                            declared: 32,
                            limit: limits.snap_length,
                        });
                    }
                    if route.route.link_type.0 > u16::MAX as u32 {
                        return Err(capture::Error::LinkTypeOutOfRange {
                            link_type: route.route.link_type.0,
                        });
                    }
                    let writer = Writer::pcapng_with_options(
                        stdout.lock(),
                        PcapNgOptions {
                            max_size: limits.snap_length,
                            ..PcapNgOptions::default()
                        },
                    )?;
                    Ok(writer)
                })(),
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

fn validate_capture_window(timeout: Duration) -> Result<(), CliError> {
    if timeout > net::capture::MAX_TIMEOUT || Instant::now().checked_add(timeout).is_none() {
        return Err(CliError::classified(net::Error::InvalidCaptureTimeout {
            timeout,
            maximum: net::capture::MAX_TIMEOUT,
        }));
    }
    Ok(())
}

pub(crate) fn drive_capture<C, F>(
    mut capture: C,
    timeout: Duration,
    limits: net::capture::Limits,
    budget: CaptureBudget,
    selector: Option<&FrameSelector>,
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
    // Two counters, because they answer different questions: `frames` counts
    // every frame the backend delivered, which is what the policy budgets
    // account for whether or not a filter keeps the frame, while `matched`
    // numbers the records actually emitted so a filtered stream stays
    // contiguous. Without a filter the two never diverge.
    let mut frames = 0_u64;
    let mut matched = 0_u64;
    let mut bytes = 0_u64;
    while frames < budget.max_frames {
        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        let frame = match capture.next_captured_frame(remaining) {
            Ok(Some(captured)) => captured.frame,
            Ok(None) => break,
            Err(source) => {
                let error = CliError::classified(source).at_sequence(matched);
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
                .at_sequence(matched),
            )
        })?;
        let next_bytes = bytes.checked_add(frame_bytes).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::new(70, "capture output byte accounting overflowed").at_sequence(matched),
            )
        })?;
        if next_bytes > budget.max_bytes {
            let error = CliError::classified(client::policy::Error::ByteLimit {
                actual: next_bytes,
                limit: budget.max_bytes,
            })
            .at_sequence(matched);
            return Err(shutdown_after_error(&mut capture, error));
        }
        bytes = next_bytes;
        let number = frames.checked_add(1).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::classified(output::contract::Error::SequenceOverflow)
                    .at_sequence(matched),
            )
        })?;
        if let Some(selector) = selector {
            match selector.keep(number, &frame) {
                Ok(true) => {}
                Ok(false) => {
                    frames = number;
                    continue;
                }
                Err(error) => {
                    return Err(shutdown_after_error(
                        &mut capture,
                        error.at_sequence_if_absent(matched),
                    ));
                }
            }
        }
        if let Err(error) = emit(frame, matched) {
            return Err(shutdown_after_error(
                &mut capture,
                error.at_sequence_if_absent(matched),
            ));
        }
        matched = matched.checked_add(1).ok_or_else(|| {
            shutdown_after_error(
                &mut capture,
                CliError::classified(output::contract::Error::SequenceOverflow)
                    .at_sequence(matched),
            )
        })?;
        frames = number;
    }
    capture
        .shutdown()
        .map_err(CliError::classified)
        .map_err(|error| error.at_sequence(matched))?;
    let statistics = capture
        .statistics()
        .validate()
        .map_err(CliError::classified)
        .map_err(|error| error.at_sequence(matched))?;
    let mut diagnostics = Vec::new();
    if statistics.has_loss() {
        if limits.overflow_policy == net::capture::OverflowPolicy::Fail {
            return Err(CliError::classified(
                statistics
                    .evidence_loss_error()
                    .expect("lossy capture statistics must produce a typed error"),
            )
            .at_sequence(matched));
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
            packets_completed: matched,
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

pub(crate) fn run_exchange(
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
            mode: mode.into(),
            ..packet::build::Options::default()
        },
        allow_permissive_live,
    };
    let client = system_client(Arc::clone(&registry), request.policy);
    let result = client
        .exchange(&packet::template::Template::new(request.packet), options)
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
        output::contract::Format::Ndjson => render_exchange_stream(result, diagnostics, stats),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Exchange,
                format: output,
            },
        )),
    }
}

fn render_exchange_stream(
    result: output::network::exchange::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    let output::network::exchange::Result {
        sent,
        responses,
        unanswered,
        unsolicited,
        undecoded,
    } = result;
    let mut sequence = 0_u64;
    for (request_index, frame) in sent.into_iter().enumerate() {
        let request_index = u64::try_from(request_index)
            .map_err(|_| CliError::classified(output::contract::Error::SequenceOverflow))?;
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::network::exchange::Event::Sent {
                request_index,
                frame,
            },
        )?;
    }
    for response in responses {
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::network::exchange::Event::Response {
                request_index: response.request_index,
                response: response.response,
                latency: response.latency,
            },
        )?;
    }
    for request_index in &unanswered {
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::network::exchange::Event::Unanswered {
                request_index: *request_index,
            },
        )?;
    }
    for frame in unsolicited {
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::network::exchange::Event::Unsolicited { frame },
        )?;
    }
    for frame in undecoded {
        emit_stream_record(
            output::contract::Command::Exchange,
            &mut sequence,
            output::network::exchange::Event::Undecoded { frame },
        )?;
    }
    emit_json_compact(
        &output::envelope::Stream::success(
            output::contract::Command::Exchange,
            sequence,
            output::network::exchange::Event::Complete { unanswered },
            diagnostics,
        )
        .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        time::{Duration, SystemTime},
    };

    use packetcraftr::{
        capture::{Frame, LinkType},
        net,
    };

    use super::{CaptureBudget, drive_capture};
    use crate::{
        filtering::{self, Capabilities, FrameSelector},
        runtime::default_registry_arc,
    };

    struct ScriptedCapture {
        ready: Option<Result<(), net::Error>>,
        frames: VecDeque<Result<Option<Frame>, net::Error>>,
        shutdown: Option<Result<(), net::Error>>,
        statistics: net::capture::Statistics,
    }

    impl net::capture::Session for ScriptedCapture {
        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), net::Error> {
            self.ready.take().unwrap_or(Ok(()))
        }

        fn next_captured_frame(
            &mut self,
            _timeout: Duration,
        ) -> Result<Option<net::capture::Captured>, net::Error> {
            self.frames
                .pop_front()
                .unwrap_or(Ok(None))
                .map(|frame| frame.map(net::capture::Captured::without_ingress_time))
        }

        fn shutdown(&mut self) -> Result<(), net::Error> {
            self.shutdown.take().unwrap_or(Ok(()))
        }

        fn statistics(&self) -> net::capture::Statistics {
            self.statistics
        }
    }

    fn test_capture_budget() -> CaptureBudget {
        CaptureBudget {
            max_frames: 10,
            max_bytes: 1024,
        }
    }

    fn frame_selector(source: &str, max_frame_bytes: usize) -> FrameSelector {
        let registry = default_registry_arc().unwrap();
        let filter = filtering::compile(source, &registry, Capabilities::frames_only()).unwrap();
        FrameSelector::new(registry, filter, max_frame_bytes)
    }

    fn scripted_frames(frames: &[Frame]) -> ScriptedCapture {
        ScriptedCapture {
            ready: Some(Ok(())),
            frames: frames
                .iter()
                .map(|frame| Ok(Some(frame.clone())))
                .chain([Ok(None)])
                .collect(),
            shutdown: Some(Ok(())),
            statistics: net::capture::Statistics::default(),
        }
    }

    #[test]
    fn capture_driver_streams_bounded_frames_and_reports_statistics() {
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![1, 2, 3]).unwrap();
        let capture = ScriptedCapture {
            ready: Some(Ok(())),
            frames: VecDeque::from([Ok(Some(frame)), Ok(None)]),
            shutdown: Some(Ok(())),
            statistics: net::capture::Statistics {
                received_frames: 1,
                received_bytes: 3,
                ..net::capture::Statistics::default()
            },
        };
        let mut rendered = Vec::new();
        let outcome = drive_capture(
            capture,
            Duration::from_millis(10),
            net::capture::Limits::default(),
            test_capture_budget(),
            None,
            |frame, sequence| {
                rendered.push((sequence, frame.bytes().to_vec()));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(rendered, vec![(0, vec![1, 2, 3])]);
        assert_eq!(outcome.stats.packets_completed, 1);
        assert_eq!(outcome.stats.bytes, 3);
        assert_eq!(outcome.stats.capture.received_frames, 1);
    }

    #[test]
    fn zero_capture_window_is_a_clean_empty_timeout() {
        let capture = ScriptedCapture {
            ready: Some(Err(net::Error::CaptureReadiness {
                message: "zero window must not wait for readiness".to_owned(),
            })),
            frames: VecDeque::from([Err(net::Error::Capture {
                message: "must not be observed".to_owned(),
            })]),
            shutdown: Some(Ok(())),
            statistics: net::capture::Statistics::default(),
        };
        let outcome = drive_capture(
            capture,
            Duration::ZERO,
            net::capture::Limits::default(),
            test_capture_budget(),
            None,
            |_, _| unreachable!(),
        )
        .unwrap();
        assert_eq!(outcome.stats.packets_completed, 0);
    }

    #[test]
    fn readiness_and_cleanup_failures_remain_structured() {
        let capture = ScriptedCapture {
            ready: Some(Err(net::Error::Privilege {
                message: "capture permission denied".to_owned(),
            })),
            frames: VecDeque::new(),
            shutdown: Some(Err(net::Error::Capture {
                message: "capture worker did not join".to_owned(),
            })),
            statistics: net::capture::Statistics::default(),
        };
        let error = drive_capture(
            capture,
            Duration::from_millis(10),
            net::capture::Limits::default(),
            test_capture_budget(),
            None,
            |_, _| Ok(()),
        )
        .unwrap_err();

        assert_eq!(error.exit_code, 4);
        assert_eq!(error.classification.code, "capability.privilege");
        assert_eq!(error.sequence, Some(0));
        assert_eq!(error.causes.len(), 2);
        assert!(error.causes[1].contains("did not join"));
    }

    #[test]
    fn capture_byte_budget_fails_before_emitting_the_excess_frame() {
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![1, 2, 3]).unwrap();
        let capture = ScriptedCapture {
            ready: Some(Ok(())),
            frames: VecDeque::from([Ok(Some(frame))]),
            shutdown: Some(Ok(())),
            statistics: net::capture::Statistics {
                received_frames: 1,
                received_bytes: 3,
                ..net::capture::Statistics::default()
            },
        };
        let mut emitted = false;
        let error = drive_capture(
            capture,
            Duration::from_millis(10),
            net::capture::Limits::default(),
            CaptureBudget {
                max_frames: 1,
                max_bytes: 2,
            },
            None,
            |_, _| {
                emitted = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(!emitted);
        assert_eq!(error.exit_code, 6);
        assert_eq!(error.classification.code, "policy.byte_limit");
        assert_eq!(error.sequence, Some(0));
    }

    #[test]
    fn capture_driver_applies_the_display_filter_and_renumbers_matches() {
        let frames = (1..=3_u8)
            .map(|index| Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![index; 3]).unwrap())
            .collect::<Vec<_>>();
        let selector = frame_selector("frame.number == 2", 1024);
        let mut rendered = Vec::new();
        let outcome = drive_capture(
            scripted_frames(&frames),
            Duration::from_millis(10),
            net::capture::Limits::default(),
            test_capture_budget(),
            Some(&selector),
            |frame, sequence| {
                rendered.push((sequence, frame.bytes().to_vec()));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(rendered, vec![(0, vec![2, 2, 2])]);
        assert_eq!(outcome.stats.packets_attempted, 3);
        assert_eq!(outcome.stats.packets_completed, 1);
        assert_eq!(outcome.stats.bytes, 9);
    }

    #[test]
    fn capture_byte_budget_counts_frames_the_filter_rejects() {
        let frames = (1..=2_u8)
            .map(|index| Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![index; 3]).unwrap())
            .collect::<Vec<_>>();
        let selector = frame_selector("frame.number == 99", 1024);
        let error = drive_capture(
            scripted_frames(&frames),
            Duration::from_millis(10),
            net::capture::Limits::default(),
            CaptureBudget {
                max_frames: 10,
                max_bytes: 5,
            },
            Some(&selector),
            |_, _| unreachable!("no frame matches the filter"),
        )
        .unwrap_err();

        assert_eq!(error.exit_code, 6);
        assert_eq!(error.classification.code, "policy.byte_limit");
        assert_eq!(error.sequence, Some(0));
    }

    #[test]
    fn capture_filter_that_cannot_dissect_a_frame_is_an_error() {
        let frames =
            [Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![0x45, 0, 0, 0]).unwrap()];
        let selector = frame_selector("frame.number == 1", 2);
        let error = drive_capture(
            scripted_frames(&frames),
            Duration::from_millis(10),
            net::capture::Limits::default(),
            test_capture_budget(),
            Some(&selector),
            |_, _| unreachable!("the frame never dissected"),
        )
        .unwrap_err();

        assert_eq!(error.exit_code, 3);
        assert_eq!(error.sequence, Some(0));
    }
}
