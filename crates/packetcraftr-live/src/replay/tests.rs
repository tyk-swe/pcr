// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::io::Cursor;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_analysis::pcap::{Reader, Writer};
use packetcraftr_network::{
    Error as LiveIoError, interface::Id as InterfaceId, link::Mode as LinkMode,
    transmit::Report as IoSendReport,
};
use packetcraftr_packet::error::{Classification, Kind};
use packetcraftr_packet::frame::{Frame, LinkType};

use super::engine::{replay_capture, replay_capture_with_selector};
use super::error::ReplayError;
use super::model::{
    ReplayAuthorizationContext, ReplayAuthorizer, ReplayLimits, ReplayOptions, ReplaySelector,
    ReplayTiming, ReplayTransmission, ReplayTransmitter,
};
use super::wire::{replay_link_mode, replay_network_envelope, validate_transmission_evidence};
use crate::BoundaryError;
use crate::clock::Clock as WorkflowClock;

#[derive(Default)]
struct RecordingAuthorizer {
    calls: usize,
    contexts: Vec<ReplayAuthorizationContext>,
    deny: bool,
}

impl ReplayAuthorizer for RecordingAuthorizer {
    fn authorize_operation(
        &mut self,
        context: ReplayAuthorizationContext,
        _frame: &Frame,
        _mode: LinkMode,
    ) -> Result<(), BoundaryError> {
        self.calls += 1;
        self.contexts.push(context);
        if self.deny {
            Err(BoundaryError::new(
                "denied by test policy",
                Classification::new("policy.test", Kind::Policy, None),
                Vec::new(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct RecordingTransmitter {
    validation_calls: usize,
    transmission_calls: usize,
    partial: bool,
    different_interface: bool,
}

impl ReplayTransmitter for RecordingTransmitter {
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        _mode: LinkMode,
        _frame: &Frame,
    ) -> Result<InterfaceId, LiveIoError> {
        self.validation_calls += 1;
        Ok(interface.clone())
    }

    fn transmit(
        &mut self,
        interface: &InterfaceId,
        _mode: LinkMode,
        frame: &Frame,
    ) -> Result<ReplayTransmission, LiveIoError> {
        self.transmission_calls += 1;
        let reported_interface = if self.different_interface {
            InterfaceId {
                name: "other0".to_owned(),
                index: interface.index + 1,
            }
        } else {
            interface.clone()
        };
        Ok(ReplayTransmission {
            interface: reported_interface,
            report: IoSendReport {
                bytes_sent: if self.partial {
                    frame.bytes().len().saturating_sub(1)
                } else {
                    frame.bytes().len()
                },
                wire_bytes: frame.bytes().clone(),
            },
        })
    }
}

#[derive(Default)]
struct RecordingClock {
    delays: Vec<Duration>,
}

impl WorkflowClock for RecordingClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.delays.push(delay);
        Ok(())
    }
}

struct RecordingSelector {
    numbers: Vec<u64>,
    skip: Option<u64>,
    keep: bool,
}

impl ReplaySelector for RecordingSelector {
    fn select(&mut self, number: u64, _frame: &Frame) -> Result<bool, BoundaryError> {
        self.numbers.push(number);
        Ok(self.keep && self.skip != Some(number))
    }
}

fn test_interface() -> InterfaceId {
    InterfaceId {
        name: "test0".to_owned(),
        index: 7,
    }
}

fn capture_reader(link_type: LinkType, frames: &[(Duration, &[u8])]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), link_type).expect("pcap writer");
    for (offset, bytes) in frames {
        writer
            .write_frame(
                &Frame::new(UNIX_EPOCH + *offset, link_type, bytes.to_vec())
                    .expect("capture frame"),
            )
            .expect("write capture frame");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("capture reader")
}

fn replay_options(timing: ReplayTiming) -> ReplayOptions {
    ReplayOptions {
        interface: test_interface(),
        link_mode: LinkMode::Auto,
        timing,
        limits: ReplayLimits::default(),
    }
}

#[test]
fn replay_timing_validation_rejects_non_finite_and_non_positive_values() {
    for timing in [
        ReplayTiming::Scaled(f64::NAN),
        ReplayTiming::Scaled(f64::INFINITY),
        ReplayTiming::Scaled(-1.0),
        ReplayTiming::FixedRate(f64::NAN),
        ReplayTiming::FixedRate(f64::INFINITY),
        ReplayTiming::FixedRate(0.0),
    ] {
        assert!(matches!(
            timing.validate(),
            Err(ReplayError::InvalidTiming { .. })
        ));
    }
}

#[test]
fn replay_network_envelope_rejects_malformed_ip_envelopes() {
    for (bytes, expected) in [
        (Vec::new(), "empty"),
        (vec![0x45; 19], "truncated IPv4"),
        (vec![0x60; 39], "truncated IPv6"),
        (vec![0x70], "unsupported IP version 7"),
    ] {
        let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).expect("capture frame");
        let error = replay_network_envelope(&frame).expect_err("malformed envelope accepted");
        assert!(error.to_string().contains(expected), "{error}");
    }

    let mut ipv4 = vec![0_u8; 20];
    ipv4[0] = 0x45;
    ipv4[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ipv4[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let envelope =
        replay_network_envelope(&Frame::new(UNIX_EPOCH, LinkType::RAW, ipv4).expect("IPv4 frame"))
            .expect("valid IPv4 envelope rejected");
    assert_eq!(envelope.source, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(envelope.destination, "10.0.0.2".parse::<IpAddr>().unwrap());

    let source: Ipv6Addr = "fd00::1".parse().unwrap();
    let destination: Ipv6Addr = "fd00::2".parse().unwrap();
    let mut ipv6 = vec![0_u8; 40];
    ipv6[0] = 0x60;
    ipv6[8..24].copy_from_slice(&source.octets());
    ipv6[24..40].copy_from_slice(&destination.octets());
    let envelope =
        replay_network_envelope(&Frame::new(UNIX_EPOCH, LinkType::RAW, ipv6).expect("IPv6 frame"))
            .expect("valid IPv6 envelope rejected");
    assert_eq!(envelope.source, IpAddr::V6(source));
    assert_eq!(envelope.destination, IpAddr::V6(destination));
}

#[test]
fn replay_link_mode_errors_preserve_sequence_and_requested_mode() {
    let error = replay_link_mode(7, LinkType(999), LinkMode::Auto).unwrap_err();
    assert!(matches!(
        error,
        ReplayError::UnsupportedLinkType {
            sequence: 7,
            link_type: 999
        }
    ));

    let error = replay_link_mode(8, LinkType::ETHERNET, LinkMode::Layer3).unwrap_err();
    assert!(matches!(
        error,
        ReplayError::LinkModeMismatch {
            sequence: 8,
            link_type,
            requested: LinkMode::Layer3
        } if link_type == LinkType::ETHERNET.0
    ));
}

#[test]
fn replay_transmission_evidence_requires_exact_wire_length_and_bytes() {
    let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0x45, 1, 2]).unwrap();
    validate_transmission_evidence(
        1,
        &frame,
        &IoSendReport {
            bytes_sent: 3,
            wire_bytes: frame.bytes().clone(),
        },
    )
    .unwrap();

    let partial = validate_transmission_evidence(
        2,
        &frame,
        &IoSendReport {
            bytes_sent: 2,
            wire_bytes: frame.bytes().clone(),
        },
    )
    .unwrap_err();
    assert!(matches!(
        partial,
        ReplayError::Transmission { sequence: 2, .. }
    ));

    let mismatch = validate_transmission_evidence(
        3,
        &frame,
        &IoSendReport {
            bytes_sent: 3,
            wire_bytes: Bytes::from_static(&[0x45, 1, 3]),
        },
    )
    .unwrap_err();
    assert!(matches!(
        mismatch,
        ReplayError::InvalidEvidence { sequence: 3, .. }
    ));
}

#[test]
fn replay_authorization_denial_has_no_later_io_side_effects() {
    let mut reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
    let mut authorizer = RecordingAuthorizer {
        deny: true,
        ..RecordingAuthorizer::default()
    };
    let mut transmitter = RecordingTransmitter::default();
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
    assert_eq!(authorizer.calls, 1);
    assert_eq!(transmitter.validation_calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
    assert!(clock.delays.is_empty());
}

#[test]
fn replay_selector_skips_authorization_and_preserves_transmitted_spacing() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::from_secs(1), &[1, 2]),
            (Duration::from_secs(2), &[3, 4, 5]),
            (Duration::from_secs(3), &[6, 7, 8, 9]),
        ],
    );
    let mut selector = RecordingSelector {
        numbers: Vec::new(),
        skip: Some(2),
        keep: true,
    };
    let mut authorizer = RecordingAuthorizer::default();
    let mut transmitter = RecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let mut emitted = Vec::new();
    let summary = replay_capture_with_selector(
        &mut reader,
        &replay_options(ReplayTiming::Original),
        Some(&mut selector),
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |evidence| {
            emitted.push(evidence);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(selector.numbers, [1, 2, 3]);
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
    assert_eq!(clock.delays, [Duration::ZERO, Duration::from_secs(2)]);
    assert_eq!(summary.frames_attempted, 3);
    assert_eq!(summary.frames_completed, 2);
    assert_eq!(summary.bytes_completed, 6);
    assert_eq!(
        emitted
            .iter()
            .map(|evidence| evidence.source_sequence)
            .collect::<Vec<_>>(),
        [0, 2]
    );
}

#[test]
fn replay_selector_skipped_frames_still_consume_the_frame_budget() {
    let mut reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::ZERO, &[1]),
            (Duration::ZERO, &[2]),
            (Duration::ZERO, &[3]),
        ],
    );
    let mut selector = RecordingSelector {
        numbers: Vec::new(),
        skip: None,
        keep: false,
    };
    let mut options = replay_options(ReplayTiming::Immediate);
    options.limits.max_frames = 2;
    let mut authorizer = RecordingAuthorizer::default();
    let mut transmitter = RecordingTransmitter::default();
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

    assert!(matches!(
        error,
        ReplayError::FrameLimit {
            sequence: 2,
            actual: 3,
            limit: 2,
        }
    ));
    assert_eq!(selector.numbers, [1, 2]);
    assert_eq!(authorizer.calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
}
