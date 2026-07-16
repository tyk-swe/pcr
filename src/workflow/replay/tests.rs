use std::convert::Infallible;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use super::wire::{replay_network_envelope, replay_wire_destinations};
use super::*;
use crate::capture::Writer;
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
    let registry = Arc::new(crate::protocol::builtin::registry().unwrap());
    let mut authorizer = SystemAuthorizer::new(
        crate::client::policy::Policy::default(),
        Arc::clone(&registry),
        true,
    );
    let error = authorizer.authorize(&frame, LinkMode::Layer3).unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
}

#[test]
fn system_authorizer_when_ipv6_routing_header_is_unsupported_rejects_frame() {
    let registry = Arc::new(crate::protocol::builtin::registry().unwrap());
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
        let mut authorizer = SystemAuthorizer::new(
            crate::client::policy::Policy::default(),
            Arc::clone(&registry),
            true,
        );
        let error = authorizer.authorize(&frame, LinkMode::Layer3).unwrap_err();
        assert_eq!(
            error.classification().code,
            "capability.replay_routing_header"
        );
    }
}

#[test]
fn raw_ip_link_types_must_match_the_packet_version() {
    let registry = Arc::new(crate::protocol::builtin::registry().unwrap());
    for (link_type, bytes, declared) in [
        (LinkType::IPV4, vec![0x60], "IPv4"),
        (LinkType::IPV6, vec![0x45], "IPv6"),
    ] {
        let frame = Frame::new(SystemTime::UNIX_EPOCH, link_type, bytes).unwrap();
        let error = replay_network_envelope(&frame).unwrap_err();
        assert!(error.to_string().contains(declared));

        let mut authorizer = SystemAuthorizer::new(
            crate::client::policy::Policy::default(),
            Arc::clone(&registry),
            true,
        );
        let error = authorizer.authorize(&frame, LinkMode::Layer3).unwrap_err();
        assert_eq!(error.classification().code, "packet.replay_network");
        assert!(error.to_string().contains(declared));
    }
}

#[derive(Default)]
struct ConfigurableRecordingAuthorizer {
    authorization_calls: usize,
    deny_authorization: bool,
}

impl ReplayAuthorizer for ConfigurableRecordingAuthorizer {
    fn authorize(
        &mut self,
        _frame: &Frame,
        _mode: LinkMode,
    ) -> Result<(), ReplayAuthorizationError> {
        self.authorization_calls += 1;
        if self.deny_authorization {
            Err(ReplayAuthorizationError::new(
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
    transmission_calls: usize,
    return_partial_send: bool,
    omit_wire_bytes: bool,
    report_different_interface: bool,
}

impl ReplayTransmitter for ConfigurableRecordingTransmitter {
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        _mode: LinkMode,
        _frame: &Frame,
    ) -> Result<InterfaceId, LiveIoError> {
        Ok(interface.clone())
    }

    fn transmit(
        &mut self,
        _interface: &InterfaceId,
        _mode: LinkMode,
        frame: &Frame,
    ) -> Result<ReplayTransmission, LiveIoError> {
        self.transmission_calls += 1;
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
                wire_bytes: (!self.omit_wire_bytes).then(|| frame.bytes().clone()),
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
fn replay_capture_when_transmitter_omits_wire_bytes_returns_invalid_evidence() {
    let mut reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1, 2])]);
    let mut authorizer = ConfigurableRecordingAuthorizer::default();
    let mut transmitter = ConfigurableRecordingTransmitter {
        omit_wire_bytes: true,
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
        &error,
        ReplayError::InvalidEvidence {
            sequence: 0,
            message
        } if message == "backend omitted exact wire bytes"
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
