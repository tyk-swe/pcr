// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::super::engine::replay_capture;
use super::super::error::ReplayError;
use super::super::model::{MAX_REPLAY_DURATION, ReplayTiming};
use super::support::{
    ConfigurableRecordingAuthorizer, ConfigurableRecordingTransmitter, RecordingClock,
    capture_reader, replay_options,
};
use packetcraftr_capture::{Frame, LinkType, Reader, Writer};
use packetcraftr_core::error::Classified;
use packetcraftr_net::{Error as LiveIoError, link::LinkMode};

#[test]
fn replay_capture_when_authorization_is_denied_does_not_sleep_or_transmit() {
    let mut reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
    let mut authorizer = ConfigurableRecordingAuthorizer {
        deny_authorization: true,
        ..ConfigurableRecordingAuthorizer::default()
    };
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &replay_options(ReplayTiming::Immediate),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        ReplayError::Authorization { sequence: 0, .. }
    ));
    assert_eq!(error.classification().code, "policy.test");
    assert_eq!(authorizer.authorization_calls, 1);
    assert_eq!(transmitter.transmission_calls, 0);
    assert!(clock.delays.is_empty());
}

#[test]
fn replay_capture_when_initial_link_type_is_unsupported_returns_typed_error() {
    let mut reader = capture_reader(LinkType::NULL, &[(Duration::ZERO, &[1])]);
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &replay_options(ReplayTiming::Immediate),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        &error,
        ReplayError::UnsupportedLinkType {
            sequence: 0,
            link_type
        } if *link_type == LinkType::NULL.0
    ));
    assert_eq!(error.classification().code, "capability.replay_link_type");
    assert_eq!(authorizer.authorization_calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
}

#[test]
fn replay_capture_when_explicit_mode_mismatches_link_type_returns_typed_error() {
    let mut reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
    let mut configured_options = replay_options(ReplayTiming::Immediate);
    configured_options.link_mode = LinkMode::Layer3;
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &configured_options,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        &error,
        ReplayError::LinkModeMismatch {
            sequence: 0,
            link_type,
            requested: LinkMode::Layer3
        } if *link_type == LinkType::ETHERNET.0
    ));
    assert_eq!(error.classification().code, "capability.replay_link_type");
    assert_eq!(authorizer.authorization_calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
}

#[test]
fn replay_capture_when_later_frame_has_unsupported_link_type_stops_before_authorization() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    let ethernet = writer.add_interface(LinkType::ETHERNET).unwrap();
    let null = writer.add_interface(LinkType::NULL).unwrap();
    let mut first = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap();
    first.interface = Some(ethernet);
    let mut second = Frame::new(UNIX_EPOCH, LinkType::NULL, vec![2]).unwrap();
    second.interface = Some(null);
    writer.write_frame(&first).unwrap();
    writer.write_frame(&second).unwrap();
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &replay_options(ReplayTiming::Immediate),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::UnsupportedLinkType {
            sequence: 1,
            link_type
        } if link_type == LinkType::NULL.0
    ));
    assert_eq!(authorizer.authorization_calls, 1);
    assert_eq!(transmitter.transmission_calls, 1);
}

#[test]
fn replay_capture_when_frame_aggregate_limit_is_exceeded_stops_before_next_send() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[(Duration::ZERO, &[1]), (Duration::ZERO, &[2])],
    );
    let mut configured_options = replay_options(ReplayTiming::Immediate);
    configured_options.limits.max_frames = 1;
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &configured_options,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::FrameLimit {
            sequence: 1,
            actual: 2,
            limit: 1
        }
    ));
    assert_eq!(authorizer.authorization_calls, 1);
    assert_eq!(transmitter.transmission_calls, 1);
}

#[test]
fn replay_capture_when_byte_aggregate_limit_is_exceeded_stops_before_next_send() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[(Duration::ZERO, &[1, 2]), (Duration::ZERO, &[3])],
    );
    let mut configured_options = replay_options(ReplayTiming::Immediate);
    configured_options.limits.max_bytes = 2;
    configured_options.limits.max_frame_bytes = 2;
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &configured_options,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::ByteLimit {
            sequence: 1,
            actual: 3,
            limit: 2
        }
    ));
    assert_eq!(authorizer.authorization_calls, 1);
    assert_eq!(transmitter.transmission_calls, 1);
}

#[test]
fn replay_capture_when_duration_limit_is_exceeded_stops_before_authorizing_next_frame() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::ZERO, &[1]),
            (MAX_REPLAY_DURATION + Duration::from_millis(1), &[2]),
        ],
    );
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &replay_options(ReplayTiming::Original),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::DurationLimit {
            sequence: 1,
            actual,
            limit: MAX_REPLAY_DURATION
        } if actual == MAX_REPLAY_DURATION + Duration::from_millis(1)
    ));
    assert_eq!(authorizer.authorization_calls, 1);
    assert_eq!(transmitter.transmission_calls, 1);
    assert_eq!(clock.delays, [Duration::ZERO]);
}

#[test]
fn infeasible_replay_delay_is_rejected_before_frame_side_effects() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[(Duration::ZERO, &[1]), (Duration::from_millis(160), &[2])],
    );
    let mut options = replay_options(ReplayTiming::Original);
    options.limits.max_duration = Duration::from_millis(200);
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter {
        transmission_delay: Duration::from_millis(60),
        ..ConfigurableRecordingTransmitter::default()
    };

    let error = replay_capture(
        &mut reader,
        &options,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap_err();

    // A loaded host can oversleep the first transmitter delay past the
    // campaign deadline, reporting sequence 0. Otherwise the prospective
    // second-frame delay is rejected at sequence 1. Both paths prevent any
    // second-frame side effects.
    assert!(matches!(
        error,
        ReplayError::DurationLimit {
            sequence: 0 | 1,
            ..
        }
    ));
    assert_eq!(authorizer.authorization_calls, 1);
    assert_eq!(transmitter.validation_calls, 1);
    assert_eq!(transmitter.transmission_calls, 1);
}

#[test]
fn slow_boundaries_record_only_a_committed_transmission_before_expiring() {
    for slow_validation in [true, false] {
        let mut reader = capture_reader(
            LinkType::ETHERNET,
            &[(Duration::ZERO, &[1]), (Duration::ZERO, &[2])],
        );
        let mut options = replay_options(ReplayTiming::Immediate);
        options.limits.max_duration = Duration::from_millis(5);
        let mut authorizer = ConfigurableRecordingAuthorizer::default();
        let mut transmitter = ConfigurableRecordingTransmitter {
            validation_delay: if slow_validation {
                Duration::from_millis(20)
            } else {
                Duration::default()
            },
            transmission_delay: if slow_validation {
                Duration::default()
            } else {
                Duration::from_millis(20)
            },
            ..ConfigurableRecordingTransmitter::default()
        };
        let mut emitted = 0;

        let error = replay_capture(
            &mut reader,
            &options,
            &mut authorizer,
            &mut transmitter,
            &mut RecordingClock::default(),
            |_| {
                emitted += 1;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ReplayError::DurationLimit { sequence: 0, .. }
        ));
        assert_eq!(authorizer.authorization_calls, 1);
        assert_eq!(transmitter.validation_calls, 1);
        assert_eq!(
            transmitter.transmission_calls,
            usize::from(!slow_validation)
        );
        assert_eq!(emitted, usize::from(!slow_validation));
    }
}

#[test]
fn slow_emit_expires_before_authorizing_or_transmitting_another_frame() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[(Duration::ZERO, &[1]), (Duration::ZERO, &[2])],
    );
    let mut options = replay_options(ReplayTiming::Immediate);
    options.limits.max_duration = Duration::from_millis(5);
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut emitted = 0;

    let error = replay_capture(
        &mut reader,
        &options,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| {
            emitted += 1;
            std::thread::sleep(Duration::from_millis(20));
            Ok(())
        },
    )
    .unwrap_err();

    assert!(matches!(
        error,
        ReplayError::DurationLimit { sequence: 0, .. }
    ));
    assert_eq!(emitted, 1);
    assert_eq!(authorizer.authorization_calls, 1);
    assert_eq!(transmitter.transmission_calls, 1);
}

#[test]
fn replay_capture_when_transmitter_reports_partial_send_returns_transmission_error() {
    let mut reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1, 2])]);
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter {
        return_partial_send: true,
        ..ConfigurableRecordingTransmitter::default()
    };
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &replay_options(ReplayTiming::Immediate),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        ReplayError::Transmission {
            sequence: 0,
            source: LiveIoError::PartialSend {
                expected: 2,
                actual: 1
            }
        }
    ));
}

#[test]
fn replay_capture_when_reported_interface_differs_from_validated_interface_rejects_evidence() {
    let mut reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1, 2])]);
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter {
        report_different_interface: true,
        ..ConfigurableRecordingTransmitter::default()
    };
    let mut emitted_evidence = false;
    let error = replay_capture(
        &mut reader,
        &replay_options(ReplayTiming::Immediate),
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| {
            emitted_evidence = true;
            Ok(())
        },
    )
    .unwrap_err();

    assert!(matches!(
        &error,
        ReplayError::InvalidEvidence {
            sequence: 0,
            message
        } if message
            == "backend reported transmission on other0 (index 8) after validating test0 (index 7)"
    ));
    assert!(!emitted_evidence);
}

#[test]
fn replay_capture_when_capture_tail_is_malformed_returns_capture_error() {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    writer
        .write_frame(&Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap())
        .unwrap();
    let mut bytes = writer.into_inner();
    bytes.extend_from_slice(&[0_u8; 8]);
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay_capture(
        &mut reader,
        &replay_options(ReplayTiming::Immediate),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(error, ReplayError::Capture { sequence: 1, .. }));
}
