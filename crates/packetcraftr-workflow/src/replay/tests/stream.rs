// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::result::Result;
use std::time::Duration;

use bytes::Bytes;

use super::super::engine::{replay_capture, replay_capture_with_selector};
use super::super::error::ReplayError;
use super::super::model::{ReplayAuthorizationContext, ReplaySelector, ReplayTiming};
use super::support::{
    ConfigurableRecordingAuthorizer, ConfigurableRecordingTransmitter, RecordingClock,
    capture_reader, replay_options,
};
use crate::BoundaryError;
use packetcraftr_capture::{Frame, LinkType};
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_net::link::LinkMode;

#[test]
fn replay_capture_with_scaled_timing_streams_exact_frames_and_reports_summary() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::from_secs(1), &[1, 2]),
            (Duration::from_millis(1_250), &[3, 4, 5]),
        ],
    );
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let mut emitted_evidence = Vec::new();
    let summary = replay_capture(
        &mut reader,
        &replay_options(ReplayTiming::Scaled(2.0)),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |event| {
            emitted_evidence.push(event);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(clock.delays, [Duration::ZERO, Duration::from_millis(500)]);
    assert_eq!(authorizer.authorization_calls, 2);
    assert_eq!(transmitter.transmission_calls, 2);
    assert_eq!(summary.frames_attempted, 2);
    assert_eq!(summary.frames_completed, 2);
    assert_eq!(summary.bytes_completed, 5);
    assert_eq!(summary.scheduled_duration, Duration::from_millis(500));
    assert_eq!(
        emitted_evidence[1].frame.bytes(),
        &Bytes::from_static(&[3, 4, 5])
    );
    assert_eq!(emitted_evidence[1].link_mode, LinkMode::Layer2);
}

struct RecordingSelector {
    numbers: Vec<u64>,
    keep: fn(u64) -> bool,
    fail_at: Option<u64>,
}

impl RecordingSelector {
    fn keeping(keep: fn(u64) -> bool) -> Self {
        Self {
            numbers: Vec::new(),
            keep,
            fail_at: None,
        }
    }
}

impl ReplaySelector for RecordingSelector {
    fn select(&mut self, number: u64, _frame: &Frame) -> Result<bool, BoundaryError> {
        self.numbers.push(number);
        if self.fail_at == Some(number) {
            return Err(BoundaryError::new(
                "selector failed by test design",
                Classification::new("cli.test_selector", Kind::Cli, None),
                Vec::new(),
            ));
        }
        Ok((self.keep)(number))
    }
}

#[test]
fn replay_with_selector_skips_frames_before_authorization_and_preserves_wire_spacing() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::from_secs(1), &[1, 2]),
            (Duration::from_secs(2), &[3, 4, 5]),
            (Duration::from_secs(3), &[6, 7, 8, 9]),
        ],
    );
    let mut selector = RecordingSelector::keeping(|number| number != 2);
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let mut emitted_evidence = Vec::new();
    let summary = replay_capture_with_selector(
        &mut reader,
        &replay_options(ReplayTiming::Original),
        Some(&mut selector),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |event| {
            emitted_evidence.push(event);
            Ok(())
        },
    )
    .unwrap();

    // Every frame is offered to the selector under its 1-based capture number.
    assert_eq!(selector.numbers, [1, 2, 3]);
    // The skipped frame never reached policy or the wire, and the policy saw
    // prospective totals that count only the frames actually transmitted.
    assert_eq!(authorizer.authorization_calls, 2);
    assert_eq!(
        authorizer.contexts,
        [
            ReplayAuthorizationContext {
                packets: 1,
                wire_bytes: 2,
            },
            ReplayAuthorizationContext {
                packets: 2,
                wire_bytes: 6,
            },
        ]
    );
    assert_eq!(transmitter.transmission_calls, 2);
    // The delay before the third frame spans the skipped frame, preserving
    // the transmitted frames' original two-second wire spacing.
    assert_eq!(clock.delays, [Duration::ZERO, Duration::from_secs(2)]);
    // Skipped frames count as attempted input but contribute no bytes.
    assert_eq!(summary.frames_attempted, 3);
    assert_eq!(summary.frames_completed, 2);
    assert_eq!(summary.bytes_completed, 6);
    assert_eq!(
        emitted_evidence
            .iter()
            .map(|evidence| evidence.source_sequence)
            .collect::<Vec<_>>(),
        [0, 2]
    );
}

#[test]
fn replay_with_selector_counts_skipped_frames_against_the_frame_budget() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::ZERO, &[1]),
            (Duration::ZERO, &[2]),
            (Duration::ZERO, &[3]),
        ],
    );
    let mut selector = RecordingSelector::keeping(|_| false);
    let mut options = replay_options(ReplayTiming::Immediate);
    options.limits.max_frames = 2;
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let error = replay_capture_with_selector(
        &mut reader,
        &options,
        Some(&mut selector),
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap_err();

    // Selection cannot extend how much input one operation reads: the third
    // frame exceeds the budget even though nothing was transmitted.
    assert!(matches!(
        error,
        ReplayError::FrameLimit {
            sequence: 2,
            actual: 3,
            limit: 2,
        }
    ));
    assert_eq!(selector.numbers, [1, 2]);
    assert_eq!(authorizer.authorization_calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
}

#[test]
fn replay_with_selector_charges_only_transmitted_frames_to_the_byte_budget() {
    let frames: &[(Duration, &[u8])] = &[
        (Duration::ZERO, &[1, 2]),
        (Duration::ZERO, &[3, 4, 5]),
        (Duration::ZERO, &[6, 7]),
    ];
    let mut options = replay_options(ReplayTiming::Immediate);
    options.limits.max_bytes = 4;
    options.limits.max_frame_bytes = 3;

    // Without selection the second frame exceeds the byte budget.
    let error = replay_capture(
        &mut capture_reader(LinkType::ETHERNET, frames),
        &options,
        &mut ConfigurableRecordingAuthorizer::default(),
        &mut ConfigurableRecordingTransmitter::default(),
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(error, ReplayError::ByteLimit { sequence: 1, .. }));

    // Skipping it leaves exactly the transmitted bytes charged.
    let mut selector = RecordingSelector::keeping(|number| number != 2);
    let summary = replay_capture_with_selector(
        &mut capture_reader(LinkType::ETHERNET, frames),
        &options,
        Some(&mut selector),
        &mut ConfigurableRecordingAuthorizer::default(),
        &mut ConfigurableRecordingTransmitter::default(),
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(summary.frames_attempted, 3);
    assert_eq!(summary.frames_completed, 2);
    assert_eq!(summary.bytes_completed, 4);
}

#[test]
fn replay_with_selector_failure_stops_the_operation_before_authorization() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[(Duration::ZERO, &[1]), (Duration::ZERO, &[2])],
    );
    let mut selector = RecordingSelector::keeping(|_| true);
    selector.fail_at = Some(2);
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let error = replay_capture_with_selector(
        &mut reader,
        &replay_options(ReplayTiming::Immediate),
        Some(&mut selector),
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(error, ReplayError::Selection { sequence: 1, .. }));
    assert_eq!(error.classification().code, "cli.test_selector");
    assert_eq!(error.sequence(), Some(1));
    // Only the first frame, which the selector accepted, was processed.
    assert_eq!(authorizer.authorization_calls, 1);
    assert_eq!(transmitter.transmission_calls, 1);
}
