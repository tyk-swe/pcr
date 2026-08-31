// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::analysis::pcap::{Reader, Writer};
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::{
    Error as LiveIoError,
    interface::Id as InterfaceId,
    link::{Capability as LinkCapability, MacAddress, Mode as LinkMode},
    route::{
        Decision, Materialized as MaterializedRoute, Plan as RoutePlan, Scope, SelectionReason,
        SystemError as RouteSystemError,
    },
    transmit::Submission,
};

use super::engine::run_with_selector;
use super::error::Error;
use super::model::{Limits, Options, Selector, Timing, Transmission, Transmitter};
use super::wire::{
    map_replay_route_error, replay_link_mode, replay_network_envelope,
    validate_transmission_evidence,
};
use crate::BoundaryError;
use crate::authorization::{Authorizer, Operation};
use crate::test_fixtures::RecordingClock;

#[derive(Default)]
struct RecordingAuthorizer {
    calls: usize,
    final_wire_calls: usize,
    budgets: Vec<(u64, u64)>,
    deny: bool,
    deny_final_wire: bool,
}

impl Authorizer for RecordingAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        self.calls += 1;
        let budget = operation.budget();
        self.budgets.push((budget.packets(), budget.wire_bytes()));
        assert!(
            matches!(operation, Operation::Replay(_)),
            "replay must submit an exact frame, got {operation:?}"
        );
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

    fn authorize_final_wire(
        &mut self,
        _frame: &Frame,
        _route: &RoutePlan,
    ) -> Result<(), BoundaryError> {
        self.final_wire_calls += 1;
        if self.deny_final_wire {
            Err(BoundaryError::new(
                "final wire route denied by test policy",
                Classification::new("policy.source_ownership", Kind::Policy, None),
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

impl Transmitter for RecordingTransmitter {
    fn plan_frame(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<MaterializedRoute, LiveIoError> {
        self.validation_calls += 1;
        Ok(MaterializedRoute {
            plan: test_route(interface, mode, frame.link_type),
            neighbor_resolution: None,
        })
    }

    fn transmit(
        &mut self,
        route: &MaterializedRoute,
        frame: &Frame,
    ) -> Result<Transmission, LiveIoError> {
        self.transmission_calls += 1;
        let interface = &route.plan.decision.interface;
        let reported_interface = if self.different_interface {
            InterfaceId {
                name: "other0".to_owned(),
                index: interface.index + 1,
            }
        } else {
            interface.clone()
        };
        Ok(Transmission {
            interface: reported_interface,
            report: Submission::start().complete(
                if self.partial {
                    frame.bytes().len().saturating_sub(1)
                } else {
                    frame.bytes().len()
                },
                frame.bytes().clone(),
            ),
        })
    }
}

struct RecordingSelector {
    numbers: Vec<u64>,
    skip: Option<u64>,
    keep: bool,
}

impl Selector for RecordingSelector {
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

fn test_route(interface: &InterfaceId, mode: LinkMode, link_type: LinkType) -> RoutePlan {
    let selected_source = "192.0.2.1".parse().expect("fixture source");
    let source_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
    RoutePlan {
        decision: Decision {
            interface: interface.clone(),
            source_mac: Some(source_mac),
            selected_source: Some(selected_source),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::InterfaceOnly,
            destination_scope: Scope::Link,
            mtu: 1_500,
            capability: LinkCapability::Layer2AndLayer3,
            link_type,
        },
        mode,
        lookup_destination: None,
        final_destination: None,
        visited_destinations: Vec::new(),
        packet_source: Some(selected_source),
        neighbor_source: None,
        neighbor_target: None,
        destination_mac: None,
        source_mac: Some(source_mac),
        neighbor_vlan_tags: Vec::new(),
        synthesized_ethernet: false,
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

fn replay_options(timing: Timing) -> Options {
    Options {
        interface: test_interface(),
        link_mode: LinkMode::Auto,
        timing,
        limits: Limits::default(),
    }
}

#[test]
fn replay_timing_validation_rejects_non_finite_and_non_positive_values() {
    for timing in [
        Timing::Scaled(f64::NAN),
        Timing::Scaled(f64::INFINITY),
        Timing::Scaled(-1.0),
        Timing::FixedRate(f64::NAN),
        Timing::FixedRate(f64::INFINITY),
        Timing::FixedRate(0.0),
    ] {
        assert!(matches!(
            timing.validate(),
            Err(Error::InvalidTiming { .. })
        ));
    }
}

#[test]
fn replay_timing_requires_capture_time_only_for_source_interval_modes() {
    assert_eq!(
        Timing::Immediate
            .delay_between(None, None, 2)
            .expect("immediate timing is independent of capture time"),
        Duration::ZERO
    );
    assert_eq!(
        Timing::FixedRate(2.0)
            .delay_between(None, None, 2)
            .expect("fixed timing is independent of capture time"),
        Duration::from_millis(500)
    );
    assert!(matches!(
        Timing::Original.delay_between(None, Some(UNIX_EPOCH), 2),
        Err(Error::TimestampUnavailable {
            source_index: 2,
            mode: "original"
        })
    ));
    assert!(matches!(
        Timing::Scaled(2.0).delay_between(Some(UNIX_EPOCH), None, 3),
        Err(Error::TimestampUnavailable {
            source_index: 3,
            mode: "scaled"
        })
    ));
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
fn replay_link_mode_errors_preserve_source_index_and_requested_mode() {
    let error = replay_link_mode(7, LinkType(999), LinkMode::Auto).unwrap_err();
    assert!(matches!(
        error,
        Error::UnsupportedLinkType {
            source_index: 7,
            link_type: 999
        }
    ));

    let error = replay_link_mode(8, LinkType::ETHERNET, LinkMode::Layer3).unwrap_err();
    assert!(matches!(
        error,
        Error::LinkModeMismatch {
            source_index: 8,
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
        &Submission::start().complete(3, frame.bytes().clone()),
    )
    .unwrap();

    let partial = validate_transmission_evidence(
        2,
        &frame,
        &Submission::start().complete(2, frame.bytes().clone()),
    )
    .unwrap_err();
    assert!(matches!(
        partial,
        Error::Transmission {
            source_index: 2,
            ..
        }
    ));

    let mismatch = validate_transmission_evidence(
        3,
        &frame,
        &Submission::start().complete(3, Bytes::from_static(&[0x45, 1, 3])),
    )
    .unwrap_err();
    assert!(matches!(
        mismatch,
        Error::Transmission {
            source_index: 3,
            ..
        }
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
    let error = run_with_selector(
        &mut reader,
        &replay_options(Timing::Immediate),
        None,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::Authorization {
            source_index: 0,
            ..
        }
    ));
    assert_eq!(authorizer.calls, 1);
    assert_eq!(authorizer.final_wire_calls, 0);
    assert_eq!(transmitter.validation_calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
    assert!(clock.delays.is_empty());
}

#[test]
fn replay_final_wire_denial_happens_after_passive_route_selection_and_before_send() {
    let mut reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
    let mut authorizer = RecordingAuthorizer {
        deny_final_wire: true,
        ..RecordingAuthorizer::default()
    };
    let mut transmitter = RecordingTransmitter::default();
    let mut clock = RecordingClock::default();

    let error = run_with_selector(
        &mut reader,
        &replay_options(Timing::Immediate),
        None,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_| Ok(()),
    )
    .expect_err("final wire authorization must reject the selected route");

    assert!(matches!(
        error,
        Error::Authorization {
            source_index: 0,
            ..
        }
    ));
    assert_eq!(authorizer.calls, 1);
    assert_eq!(authorizer.final_wire_calls, 1);
    assert_eq!(transmitter.validation_calls, 1);
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
    let summary = run_with_selector(
        &mut reader,
        &replay_options(Timing::Original),
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
    assert_eq!(authorizer.budgets, [(1, 2), (2, 6)]);
    assert_eq!(transmitter.transmission_calls, 2);
    assert_eq!(clock.delays, [Duration::ZERO, Duration::from_secs(2)]);
    assert_eq!(summary.frames_read, 3);
    assert_eq!(summary.frames_transmitted, 2);
    assert_eq!(summary.bytes_transmitted, 6);
    assert_eq!(
        emitted
            .iter()
            .map(|evidence| evidence.source_index)
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
    let mut options = replay_options(Timing::Immediate);
    options.limits.max_source_frames = 2;
    let mut authorizer = RecordingAuthorizer::default();
    let mut transmitter = RecordingTransmitter::default();
    let error = run_with_selector(
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
        Error::SourceFrameLimit {
            source_index: 2,
            actual: 3,
            limit: 2,
        }
    ));
    assert_eq!(selector.numbers, [1, 2]);
    assert_eq!(authorizer.calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
}

/// Both arms of the replay route-selection mapping retain the route adapter's
/// own refusal as a source, so the platform diagnostic reaches `causes()`
/// instead of being dropped when it stops being restated in `message`.
#[test]
fn replay_route_selection_failures_retain_the_route_adapter_refusal() {
    let destination = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let unreachable = map_replay_route_error(RouteSystemError::RouteNotFound { destination });

    assert_eq!(
        unreachable.to_string(),
        "packet transmission failed: replay route selection failed"
    );
    assert_eq!(unreachable.classification().code, "io.send");
    assert_eq!(unreachable.causes(), ["no route to 203.0.113.9 was found"]);

    // The refusal keeps reaching a consumer through the replay wrapper the
    // engine publishes it in.
    let published = Error::Transmission {
        source_index: 0,
        source: unreachable,
    };
    assert_eq!(
        published.causes(),
        [
            "packet transmission failed: replay route selection failed",
            "no route to 203.0.113.9 was found",
        ]
    );

    // An operating-system refusal keeps its own nested diagnostic too.
    let refused = map_replay_route_error(RouteSystemError::OperatingSystem {
        operation: "RTM_GETROUTE",
        message: "the operating system refused the request".to_owned(),
        source: Some(Arc::new(std::io::Error::other("operation not permitted"))),
    });
    assert_eq!(
        refused.causes(),
        [
            "native operation RTM_GETROUTE failed: the operating system refused the request",
            "operation not permitted",
        ]
    );

    // The capability arm keeps naming the replay boundary and publishes the
    // adapter's text once, in `causes`.
    let unsupported = map_replay_route_error(RouteSystemError::Unsupported {
        message: "native route selection is off".to_owned(),
    });
    assert_eq!(
        unsupported.to_string(),
        "live packet I/O is unavailable: the native route adapter cannot select a replay route"
    );
    assert_eq!(unsupported.classification().kind, Kind::Capability);
    assert_eq!(
        unsupported.causes(),
        ["native route selection is unavailable: native route selection is off"]
    );
}
