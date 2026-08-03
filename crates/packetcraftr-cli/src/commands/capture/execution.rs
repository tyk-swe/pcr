// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr::{capture::Frame, client, net, output, packet};

use crate::errors::CliError;
use crate::filtering::FrameSelector;

#[derive(Debug)]
pub(super) struct CaptureOutcome {
    pub(super) diagnostics: Vec<packet::diagnostic::Diagnostic>,
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

pub(super) fn drive_capture<C, F>(
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
    // account for whether or not the display filter keeps the frame, while
    // `matched` numbers the records actually emitted so a filtered stream
    // stays contiguous. Without a display filter the two never diverge.
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

pub(super) fn shutdown_after_error<C: net::capture::Session>(
    capture: &mut C,
    error: CliError,
) -> CliError {
    match capture.shutdown() {
        Ok(()) => error,
        Err(cleanup) => error.with_cleanup(cleanup),
    }
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
    fn capture_byte_budget_counts_frames_the_display_filter_rejects() {
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
            |_, _| unreachable!("no frame matches the display filter"),
        )
        .unwrap_err();

        assert_eq!(error.exit_code, 6);
        assert_eq!(error.classification.code, "policy.byte_limit");
        assert_eq!(error.sequence, Some(0));
    }

    #[test]
    fn display_filter_that_cannot_dissect_a_frame_is_an_error() {
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
