// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use super::wire::{
    replay_link_mode, replay_network_envelope, replay_wire_destinations,
    validate_transmission_evidence,
};
use super::*;
use crate::BoundaryError;
use packetcraftr_capture::Writer;
use packetcraftr_packet::{Packet, layer::Raw};
use packetcraftr_protocol::{network::Ipv4, transport::Udp};
use std::result::Result;

#[test]
fn replay_timing_for_valid_modes_calculates_expected_delay() {
    let previous = UNIX_EPOCH + Duration::from_secs(1);
    let current = previous + Duration::from_millis(250);
    assert_eq!(
        ReplayTiming::Original
            .delay_between(previous, current)
            .unwrap(),
        Duration::from_millis(250)
    );
    assert_eq!(
        ReplayTiming::Scaled(2.0)
            .delay_between(previous, current)
            .unwrap(),
        Duration::from_millis(500)
    );
    assert_eq!(
        ReplayTiming::FixedRate(4.0)
            .delay_between(previous, current)
            .unwrap(),
        Duration::from_millis(250)
    );
    assert_eq!(
        ReplayTiming::Immediate
            .delay_between(previous, current)
            .unwrap(),
        Duration::ZERO
    );
    assert_eq!(
        ReplayTiming::Scaled(f64::MIN_POSITIVE)
            .delay_between(previous, previous)
            .unwrap(),
        Duration::ZERO
    );
}

#[test]
fn replay_timing_with_non_positive_or_unrepresentable_values_returns_invalid_timing() {
    let previous = UNIX_EPOCH + Duration::from_secs(1);
    let current = previous + Duration::from_millis(250);
    let error = ReplayTiming::Scaled(0.0)
        .delay_between(previous, current)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid replay timing: invalid replay scaled value 0"
    );
    assert_eq!(error.classification().code, "cli.replay_limit");

    let error = ReplayTiming::FixedRate(f64::MAX)
        .delay_between(previous, current)
        .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::InvalidTiming {
            mode: "fixed_rate",
            value
        } if value == f64::MAX
    ));
    let error = ReplayTiming::Scaled(f64::MIN_POSITIVE)
        .delay_between(previous, current)
        .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::InvalidTiming {
            mode: "scaled",
            value
        } if value == f64::MIN_POSITIVE
    ));
}

#[test]
fn system_authorizer_when_raw_ipv4_targets_public_address_denies_frame() {
    let mut ipv4 = vec![0_u8; 20];
    ipv4[0] = 0x45;
    ipv4[16..20].copy_from_slice(&[8, 8, 8, 8]);
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, ipv4).unwrap();
    assert_eq!(
        replay_wire_destinations(&frame).unwrap().addresses,
        [IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
    );
    let registry = Arc::new(packetcraftr_protocol::builtin::registry().unwrap());
    let authorizer = SystemAuthorizer::new(
        packetcraftr_client::policy::Policy::default(),
        Arc::clone(&registry),
        true,
    );
    let error = authorizer
        .authorize_frame(&frame, LinkMode::Layer3)
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
}

fn authorized_raw_frame() -> Frame {
    let registry = Arc::new(packetcraftr_protocol::builtin::registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"replay")));
    let built = Builder::new(registry)
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    Frame::new(UNIX_EPOCH, LinkType::RAW, built.bytes).unwrap()
}

#[test]
fn system_authorizer_enforces_cumulative_policy_packet_and_byte_budgets() {
    let frame = authorized_raw_frame();
    let registry = Arc::new(packetcraftr_protocol::builtin::registry().unwrap());
    let mut packet_policy = packetcraftr_client::policy::Policy {
        max_packets_per_operation: 1,
        allow_permissive_packets: true,
        ..packetcraftr_client::policy::Policy::default()
    };
    packet_policy.max_bytes_per_operation = u64::MAX;
    let mut authorizer = SystemAuthorizer::new(packet_policy, Arc::clone(&registry), true);
    let error = authorizer
        .authorize_operation(
            ReplayAuthorizationContext {
                packets: 2,
                wire_bytes: u64::from(frame.captured_length()),
            },
            &frame,
            LinkMode::Layer3,
        )
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.packet_limit");

    let mut byte_policy = packetcraftr_client::policy::Policy {
        max_packets_per_operation: 10,
        max_bytes_per_operation: u64::from(frame.captured_length()),
        allow_permissive_packets: true,
        ..packetcraftr_client::policy::Policy::default()
    };
    byte_policy.allow_public_destinations = false;
    let mut authorizer = SystemAuthorizer::new(byte_policy, registry, true);
    let error = authorizer
        .authorize_operation(
            ReplayAuthorizationContext {
                packets: 1,
                wire_bytes: u64::from(frame.captured_length()) + 1,
            },
            &frame,
            LinkMode::Layer3,
        )
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.byte_limit");
}

#[test]
fn system_authorizer_uses_engine_budget_for_each_replay_operation() {
    let frame = authorized_raw_frame();
    let bytes = frame.bytes().clone();
    let registry = Arc::new(packetcraftr_protocol::builtin::registry().unwrap());
    let policy = packetcraftr_client::policy::Policy {
        max_packets_per_operation: 1,
        max_bytes_per_operation: u64::MAX,
        allow_permissive_packets: true,
        ..packetcraftr_client::policy::Policy::default()
    };
    let mut authorizer = SystemAuthorizer::new(policy, registry, true);
    let mut options = replay_options(ReplayTiming::Immediate);
    options.link_mode = LinkMode::Layer3;
    let mut first_reader = capture_reader(
        LinkType::RAW,
        &[
            (Duration::ZERO, bytes.as_ref()),
            (Duration::ZERO, bytes.as_ref()),
        ],
    );
    let mut transmitter = ConfigurableRecordingTransmitter::default();

    let error = replay_capture(
        &mut first_reader,
        &options,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        &error,
        ReplayError::Authorization { sequence: 1, .. }
    ));
    assert_eq!(error.classification().code, "policy.packet_limit");
    assert_eq!(transmitter.transmission_calls, 1);

    let mut second_reader = capture_reader(LinkType::RAW, &[(Duration::ZERO, bytes.as_ref())]);
    let summary = replay_capture(
        &mut second_reader,
        &options,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap();

    assert_eq!(summary.frames_completed, 1);
    assert_eq!(transmitter.transmission_calls, 2);
}

#[test]
fn system_authorizer_when_ipv6_routing_header_is_unsupported_rejects_frame() {
    let registry = Arc::new(packetcraftr_protocol::builtin::registry().unwrap());
    for mut unsupported in [vec![0_u8; 48], vec![0_u8; 40]] {
        unsupported[0] = 0x60;
        unsupported[6] = 43;
        unsupported[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        if unsupported.len() == 48 {
            unsupported[40] = 59;
            unsupported[42] = 0;
        }
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, unsupported).unwrap();
        assert!(
            replay_wire_destinations(&frame)
                .unwrap()
                .has_unsupported_routing_header
        );
        let authorizer = SystemAuthorizer::new(
            packetcraftr_client::policy::Policy::default(),
            Arc::clone(&registry),
            true,
        );
        let error = authorizer
            .authorize_frame(&frame, LinkMode::Layer3)
            .unwrap_err();
        assert_eq!(
            error.classification().code,
            "capability.replay_routing_header"
        );
    }
}

#[test]
fn replay_srh_validation_requires_the_header_to_name_the_active_segment() {
    let active: Ipv6Addr = "fd00::10".parse().unwrap();
    let final_destination: Ipv6Addr = "fd00::20".parse().unwrap();
    let mut bytes = vec![0_u8; 80];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&40_u16.to_be_bytes());
    bytes[6] = 43;
    bytes[24..40].copy_from_slice(&active.octets());
    bytes[40] = 59;
    bytes[41] = 4;
    bytes[42] = 4;
    bytes[43] = 1;
    bytes[44] = 1;
    bytes[48..64].copy_from_slice(&final_destination.octets());
    bytes[64..80].copy_from_slice(&active.octets());
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes.clone()).unwrap();

    let destinations = replay_wire_destinations(&frame).unwrap();
    assert!(!destinations.has_unsupported_routing_header);
    assert!(
        destinations
            .addresses
            .contains(&IpAddr::V6(final_destination))
    );

    bytes[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    let malformed = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).unwrap();
    assert!(
        replay_wire_destinations(&malformed)
            .unwrap()
            .has_unsupported_routing_header
    );
}

#[test]
fn raw_ip_link_types_must_match_the_packet_version() {
    let registry = Arc::new(packetcraftr_protocol::builtin::registry().unwrap());
    for (link_type, bytes, declared) in [
        (LinkType::IPV4, vec![0x60], "IPv4"),
        (LinkType::IPV6, vec![0x45], "IPv6"),
    ] {
        let frame = Frame::new(SystemTime::UNIX_EPOCH, link_type, bytes).unwrap();
        let error = replay_network_envelope(&frame).unwrap_err();
        assert!(error.to_string().contains(declared));

        let authorizer = SystemAuthorizer::new(
            packetcraftr_client::policy::Policy::default(),
            Arc::clone(&registry),
            true,
        );
        let error = authorizer
            .authorize_frame(&frame, LinkMode::Layer3)
            .unwrap_err();
        assert_eq!(error.classification().code, "packet.replay_network");
        assert!(error.to_string().contains(declared));
    }
}

#[test]
fn replay_timing_validation_rejects_every_non_finite_or_non_positive_factor() {
    for timing in [
        ReplayTiming::Scaled(f64::NAN),
        ReplayTiming::Scaled(f64::INFINITY),
        ReplayTiming::Scaled(f64::NEG_INFINITY),
        ReplayTiming::Scaled(-1.0),
        ReplayTiming::FixedRate(f64::NAN),
        ReplayTiming::FixedRate(f64::INFINITY),
        ReplayTiming::FixedRate(f64::NEG_INFINITY),
        ReplayTiming::FixedRate(-1.0),
        ReplayTiming::FixedRate(0.0),
    ] {
        assert!(
            matches!(timing.validate(), Err(ReplayError::InvalidTiming { .. })),
            "{timing:?}"
        );
    }
}

#[test]
fn replay_timing_handles_backward_capture_timestamps_without_delay() {
    let later = UNIX_EPOCH + Duration::from_secs(2);
    let earlier = UNIX_EPOCH + Duration::from_secs(1);
    assert_eq!(
        ReplayTiming::Original
            .delay_between(later, earlier)
            .unwrap(),
        Duration::ZERO
    );
    assert_eq!(
        ReplayTiming::Scaled(3.0)
            .delay_between(later, earlier)
            .unwrap(),
        Duration::ZERO
    );
}

#[test]
fn replay_limit_validation_names_each_zero_limit() {
    for field in ["max_frames", "max_bytes", "max_frame_bytes"] {
        let mut limits = ReplayLimits::default();
        match field {
            "max_frames" => limits.max_frames = 0,
            "max_bytes" => limits.max_bytes = 0,
            "max_frame_bytes" => limits.max_frame_bytes = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            limits.validate(),
            Err(ReplayError::InvalidLimit {
                field: actual,
                value: 0,
                reason: "must be non-zero",
            }) if actual == field
        ));
    }
}

#[test]
fn replay_limit_validation_rejects_inconsistent_frame_and_duration_bounds() {
    let error = ReplayLimits {
        max_bytes: 63,
        max_frame_bytes: 64,
        ..ReplayLimits::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::InvalidLimit {
            field: "max_frame_bytes",
            value: 64,
            reason: "cannot exceed max_bytes",
        }
    ));

    for max_duration in [
        Duration::ZERO,
        MAX_REPLAY_DURATION.saturating_add(Duration::from_nanos(1)),
    ] {
        assert!(matches!(
            ReplayLimits {
                max_duration,
                ..ReplayLimits::default()
            }
            .validate(),
            Err(ReplayError::InvalidDuration { value, .. }) if value == max_duration
        ));
    }
}

#[test]
fn replay_default_limits_are_valid_and_finite() {
    let limits = ReplayLimits::default().validate().unwrap();
    assert!(limits.max_frames > 0);
    assert!(limits.max_bytes >= limits.max_frame_bytes as u64);
    assert!(limits.max_duration <= MAX_REPLAY_DURATION);
}

#[test]
fn replay_network_envelope_extracts_ipv4_and_ipv6_endpoints() {
    let mut ipv4 = vec![0_u8; 20];
    ipv4[0] = 0x45;
    ipv4[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ipv4[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let envelope =
        replay_network_envelope(&Frame::new(UNIX_EPOCH, LinkType::RAW, ipv4).unwrap()).unwrap();
    assert_eq!(envelope.source, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(envelope.destination, "10.0.0.2".parse::<IpAddr>().unwrap());

    let source: Ipv6Addr = "fd00::1".parse().unwrap();
    let destination: Ipv6Addr = "fd00::2".parse().unwrap();
    let mut ipv6 = vec![0_u8; 40];
    ipv6[0] = 0x60;
    ipv6[8..24].copy_from_slice(&source.octets());
    ipv6[24..40].copy_from_slice(&destination.octets());
    let envelope =
        replay_network_envelope(&Frame::new(UNIX_EPOCH, LinkType::RAW, ipv6).unwrap()).unwrap();
    assert_eq!(envelope.source, IpAddr::V6(source));
    assert_eq!(envelope.destination, IpAddr::V6(destination));
}

#[test]
fn replay_network_envelope_rejects_empty_truncated_and_unknown_packets() {
    for (bytes, expected) in [
        (Vec::new(), "empty"),
        (vec![0x45; 19], "truncated IPv4"),
        (vec![0x60; 39], "truncated IPv6"),
        (vec![0x70], "unsupported IP version 7"),
    ] {
        let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap();
        let error = replay_network_envelope(&frame).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn replay_wire_destinations_walks_vlan_and_ipv4_source_routes() {
    let final_destination = Ipv4Addr::new(10, 0, 0, 9);
    let route_destination = Ipv4Addr::new(10, 0, 0, 10);
    let mut bytes = vec![0_u8; 18 + 28];
    bytes[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
    bytes[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[18] = 0x47;
    bytes[34..38].copy_from_slice(&final_destination.octets());
    bytes[38..45].copy_from_slice(&[
        131,
        7,
        4,
        route_destination.octets()[0],
        route_destination.octets()[1],
        route_destination.octets()[2],
        route_destination.octets()[3],
    ]);
    let destinations =
        replay_wire_destinations(&Frame::new(UNIX_EPOCH, LinkType::ETHERNET, bytes).unwrap())
            .unwrap();
    assert_eq!(
        destinations.addresses,
        [IpAddr::V4(final_destination), IpAddr::V4(route_destination)]
    );
    assert!(!destinations.has_unsupported_routing_header);
}

#[test]
fn replay_wire_destinations_fail_closed_on_malformed_ipv4_options() {
    let mut bytes = vec![0_u8; 24];
    bytes[0] = 0x46;
    bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
    bytes[20..24].copy_from_slice(&[131, 1, 0, 0]);
    let error =
        match replay_wire_destinations(&Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap()) {
            Ok(_) => panic!("malformed source-route option was accepted"),
            Err(error) => error,
        };
    assert!(error.to_string().contains("invalid length 1"));
}

#[test]
fn replay_wire_destinations_walks_non_routing_ipv6_extensions() {
    let destination: Ipv6Addr = "fd00::2".parse().unwrap();
    let mut bytes = vec![0_u8; 64];
    bytes[0] = 0x60;
    bytes[6] = 0;
    bytes[24..40].copy_from_slice(&destination.octets());
    bytes[40] = 44;
    bytes[41] = 0;
    bytes[48] = 51;
    bytes[56] = 59;
    bytes[57] = 0;
    let destinations =
        replay_wire_destinations(&Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap()).unwrap();
    assert_eq!(destinations.addresses, [IpAddr::V6(destination)]);
    assert!(!destinations.has_unsupported_routing_header);
}

#[test]
fn replay_wire_destinations_ignores_truncated_non_routing_extensions() {
    for (next_header, length) in [(44, 44), (51, 41), (0, 44), (60, 44)] {
        let mut bytes = vec![0_u8; length];
        bytes[0] = 0x60;
        bytes[6] = next_header;
        let result =
            replay_wire_destinations(&Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap())
                .unwrap();
        assert!(!result.has_unsupported_routing_header, "{next_header}");
    }
}

#[test]
fn replay_link_mode_accepts_only_compatible_link_types() {
    for (link_type, expected) in [
        (LinkType::ETHERNET, LinkMode::Layer2),
        (LinkType::RAW, LinkMode::Layer3),
        (LinkType::BSD_RAW, LinkMode::Layer3),
        (LinkType::IPV4, LinkMode::Layer3),
        (LinkType::IPV6, LinkMode::Layer3),
    ] {
        assert_eq!(
            replay_link_mode(3, link_type, LinkMode::Auto).unwrap(),
            expected
        );
        assert_eq!(replay_link_mode(3, link_type, expected).unwrap(), expected);
    }
}

#[test]
fn replay_link_mode_reports_unsupported_and_mismatched_types_with_sequence() {
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
fn replay_transmission_evidence_requires_exact_length_and_bytes() {
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
fn replay_frame_errors_expose_their_source_sequence() {
    let errors = [
        ReplayError::FrameLimit {
            sequence: 9,
            actual: 2,
            limit: 1,
        },
        ReplayError::ByteLimit {
            sequence: 9,
            actual: 2,
            limit: 1,
        },
        ReplayError::FrameSizeLimit {
            sequence: 9,
            actual: 2,
            limit: 1,
        },
        ReplayError::DurationLimit {
            sequence: 9,
            actual: Duration::from_secs(1),
            limit: Duration::ZERO,
        },
        ReplayError::UnsupportedLinkType {
            sequence: 9,
            link_type: 999,
        },
        ReplayError::Timing {
            sequence: 9,
            mode: "scaled",
            value: 0.0,
        },
        ReplayError::InvalidEvidence {
            sequence: 9,
            message: "bad".to_owned(),
        },
        ReplayError::Clock {
            sequence: 9,
            message: "bad".to_owned(),
        },
        ReplayError::output(9, "bad"),
    ];
    for error in errors {
        assert_eq!(error.sequence(), Some(9), "{error}");
    }
    assert_eq!(
        ReplayError::InvalidTiming {
            mode: "scaled",
            value: 0.0
        }
        .sequence(),
        None
    );
}

#[test]
fn replay_errors_map_to_stable_classifications() {
    let cases = [
        (
            ReplayError::InvalidLimit {
                field: "max_frames",
                value: 0,
                reason: "must be non-zero",
            },
            "cli.replay_limit",
            Kind::Cli,
        ),
        (
            ReplayError::FrameLimit {
                sequence: 1,
                actual: 2,
                limit: 1,
            },
            "policy.replay_limit",
            Kind::Policy,
        ),
        (
            ReplayError::FrameSizeLimit {
                sequence: 1,
                actual: 2,
                limit: 1,
            },
            "packet.capture_size",
            Kind::Packet,
        ),
        (
            ReplayError::Timing {
                sequence: 1,
                mode: "scaled",
                value: 0.0,
            },
            "packet.replay_timing",
            Kind::Packet,
        ),
        (
            ReplayError::UnsupportedLinkType {
                sequence: 1,
                link_type: 999,
            },
            "capability.replay_link_type",
            Kind::Capability,
        ),
        (
            ReplayError::InvalidEvidence {
                sequence: 1,
                message: "bad".to_owned(),
            },
            "internal.replay_evidence",
            Kind::Internal,
        ),
        (
            ReplayError::Clock {
                sequence: 1,
                message: "bad".to_owned(),
            },
            "io.replay",
            Kind::Io,
        ),
    ];
    for (error, code, kind) in cases {
        assert_eq!(error.classification().code, code, "{error}");
        assert_eq!(error.classification().kind, kind, "{error}");
    }
}

#[derive(Default)]
struct ConfigurableRecordingAuthorizer {
    authorization_calls: usize,
    contexts: Vec<ReplayAuthorizationContext>,
    deny_authorization: bool,
}

impl ReplayAuthorizer for ConfigurableRecordingAuthorizer {
    fn authorize_operation(
        &mut self,
        context: ReplayAuthorizationContext,
        _frame: &Frame,
        _mode: LinkMode,
    ) -> Result<(), BoundaryError> {
        self.authorization_calls += 1;
        self.contexts.push(context);
        if self.deny_authorization {
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
struct ConfigurableRecordingTransmitter {
    validation_calls: usize,
    transmission_calls: usize,
    validation_delay: Duration,
    transmission_delay: Duration,
    return_partial_send: bool,
    report_different_interface: bool,
}

impl ReplayTransmitter for ConfigurableRecordingTransmitter {
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        _mode: LinkMode,
        _frame: &Frame,
    ) -> Result<InterfaceId, LiveIoError> {
        self.validation_calls += 1;
        if !self.validation_delay.is_zero() {
            std::thread::sleep(self.validation_delay);
        }
        Ok(interface.clone())
    }

    fn transmit(
        &mut self,
        _interface: &InterfaceId,
        _mode: LinkMode,
        frame: &Frame,
    ) -> Result<ReplayTransmission, LiveIoError> {
        self.transmission_calls += 1;
        if !self.transmission_delay.is_zero() {
            std::thread::sleep(self.transmission_delay);
        }
        Ok(ReplayTransmission {
            interface: if self.report_different_interface {
                InterfaceId {
                    name: "other0".to_owned(),
                    index: _interface.index + 1,
                }
            } else {
                _interface.clone()
            },
            report: IoSendReport {
                bytes_sent: if self.return_partial_send {
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

fn test_interface() -> InterfaceId {
    InterfaceId {
        name: "test0".to_owned(),
        index: 7,
    }
}

fn capture_reader(link_type: LinkType, frames: &[(Duration, &[u8])]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), link_type).unwrap();
    for (timestamp, bytes) in frames {
        writer
            .write_frame(&Frame::new(UNIX_EPOCH + *timestamp, link_type, bytes.to_vec()).unwrap())
            .unwrap();
    }
    Reader::new(Cursor::new(writer.into_inner())).unwrap()
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
fn slow_transmitter_boundaries_expire_before_emit_or_a_later_frame() {
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
        assert_eq!(emitted, 0);
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
