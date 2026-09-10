// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::protocol::{link::Ethernet, network::Ipv4};
use packetcraftr_core::{layer::Raw, packet::Packet};
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::{
    Error,
    capture::{self, Session as _},
    link::{Capability, MacAddress, Mode},
    neighbor,
    route::{
        Decision, Materialized, Options, Plan, Provider, Scope, SelectionReason, plan as plan_route,
    },
    transmit::{
        Frame, Layer2Frame, Layer2Sender, Layer3Frame, Layer3Sender, ModeSender, Report, Sender,
    },
};

#[derive(Clone, Copy, Debug)]
struct RouteFailure;

impl fmt::Display for RouteFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("route fixture failed")
    }
}

impl std::error::Error for RouteFailure {}

#[derive(Clone)]
struct Routes {
    decision: Result<Decision, RouteFailure>,
    interface_decision: Result<Option<Decision>, RouteFailure>,
    lookup_calls: Arc<AtomicUsize>,
    interface_calls: Arc<AtomicUsize>,
}

impl Provider for Routes {
    type Error = RouteFailure;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        self.lookup_calls.fetch_add(1, Ordering::SeqCst);
        self.decision.clone()
    }

    fn lookup_interface(&self, _interface: &InterfaceId) -> Result<Option<Decision>, Self::Error> {
        self.interface_calls.fetch_add(1, Ordering::SeqCst);
        self.interface_decision.clone()
    }
}

fn interface() -> InterfaceId {
    InterfaceId {
        name: "fixture0".to_owned(),
        index: 4,
    }
}

fn decision(capability: Capability) -> Decision {
    Decision {
        interface: interface(),
        source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        preferred_source: None,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        selection_reason: SelectionReason::Gateway,
        destination_scope: Scope::Private,
        mtu: 1_500,
        capability,
        link_type: LinkType::ETHERNET,
    }
}

fn routes(decision: Result<Decision, RouteFailure>) -> Routes {
    Routes {
        interface_decision: decision.clone().map(Some),
        decision,
        lookup_calls: Arc::new(AtomicUsize::new(0)),
        interface_calls: Arc::new(AtomicUsize::new(0)),
    }
}

fn planned(mode: Mode) -> Plan {
    Plan {
        decision: decision(Capability::Layer2AndLayer3),
        mode,
        lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
        final_destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
        visited_destinations: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))],
        packet_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        neighbor_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        neighbor_target: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        destination_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 9])),
        source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
        neighbor_vlan_tags: Vec::new(),
        synthesized_ethernet: false,
    }
}

fn materialized(mode: Mode) -> Materialized {
    Materialized {
        plan: planned(mode),
        neighbor_resolution: None,
    }
}

#[test]
fn capture_limits_validate_each_bound_and_cross_field_constraint() {
    let defaults = capture::Limits::default();
    for (field, limits) in [
        (
            "max_frames",
            capture::Limits {
                max_frames: 0,
                ..defaults
            },
        ),
        (
            "max_bytes",
            capture::Limits {
                max_bytes: 0,
                ..defaults
            },
        ),
        (
            "snap_length",
            capture::Limits {
                snap_length: 0,
                ..defaults
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidCaptureQueueLimit { field: actual, .. }) if actual == field
        ));
    }

    for (field, limits) in [
        (
            "max_frames",
            capture::Limits {
                max_frames: capture::MAX_CAPTURE_QUEUE_FRAMES + 1,
                ..defaults
            },
        ),
        (
            "max_bytes",
            capture::Limits {
                max_bytes: capture::MAX_CAPTURE_QUEUE_BYTES + 1,
                ..defaults
            },
        ),
        (
            "snap_length",
            capture::Limits {
                snap_length: capture::MAX_SNAP_LENGTH + 1,
                ..defaults
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidCaptureQueueLimit { field: actual, .. }) if actual == field
        ));
    }

    assert!(matches!(
        capture::Limits {
            max_bytes: 127,
            snap_length: 128,
            ..defaults
        }
        .validate(),
        Err(Error::InvalidCaptureQueueLimit {
            field: "snap_length",
            reason: "cannot exceed max_bytes",
            ..
        })
    ));
}

#[test]
fn capture_statistics_distinguish_complete_receiver_loss_and_queue_overflow() {
    let complete = capture::Statistics {
        received_frames: 2,
        received_bytes: 20,
        ..capture::Statistics::default()
    };
    assert!(complete.evidence_loss_error().is_none());
    complete.validate().expect("complete statistics");

    let receiver_loss = capture::Statistics {
        dropped_frames: 3,
        dropped_bytes: 30,
        receiver_dropped_frames: 2,
        ..capture::Statistics::default()
    };
    assert!(matches!(
        receiver_loss.evidence_loss_error(),
        Some(Error::CaptureEvidenceLoss {
            dropped_frames: 3,
            receiver_dropped_frames: 2,
            ..
        })
    ));

    let overflow = capture::Statistics {
        overflow_events: 2,
        ..capture::Statistics::default()
    };
    assert!(matches!(
        overflow.evidence_loss_error(),
        Some(Error::CaptureQueueOverflow {
            overflow_events: 2,
            ..
        })
    ));

    assert!(matches!(
        capture::Statistics {
            dropped_frames: 1,
            receiver_dropped_frames: 2,
            ..capture::Statistics::default()
        }
        .validate(),
        Err(Error::InvalidCaptureStatistics { .. })
    ));
}

#[test]
fn capture_statistics_checked_add_is_complete_and_detects_overflow() {
    let first = capture::Statistics {
        received_frames: 1,
        received_bytes: 2,
        dropped_frames: 7,
        dropped_bytes: 4,
        overflow_events: 5,
        receiver_dropped_frames: 6,
    };
    let second = capture::Statistics {
        received_frames: 10,
        received_bytes: 20,
        dropped_frames: 70,
        dropped_bytes: 40,
        overflow_events: 50,
        receiver_dropped_frames: 60,
    };
    assert_eq!(
        first.checked_add(second),
        Some(capture::Statistics {
            received_frames: 11,
            received_bytes: 22,
            dropped_frames: 77,
            dropped_bytes: 44,
            overflow_events: 55,
            receiver_dropped_frames: 66,
        })
    );

    assert_eq!(
        capture::Statistics {
            receiver_dropped_frames: u64::MAX,
            ..capture::Statistics::default()
        }
        .checked_add(capture::Statistics {
            receiver_dropped_frames: 1,
            ..capture::Statistics::default()
        }),
        None
    );
}

#[derive(Debug)]
struct EmptySession {
    metadata: capture::Metadata,
    polls: Arc<AtomicUsize>,
}

impl capture::Session for EmptySession {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<capture::Captured>, Error> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

#[test]
fn cancellable_capture_backs_off_after_early_empty_polls() {
    for (timeout, maximum_polls) in [
        (Duration::ZERO, 1),
        (Cancellation::POLL_INTERVAL / 5, 1),
        (Cancellation::POLL_INTERVAL * 4, 4),
    ] {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut session = capture::Cancellable::new(
            EmptySession {
                metadata: capture::Metadata {
                    interface: interface(),
                    link_type: LinkType::IPV4,
                    snap_length: 128,
                },
                polls: polls.clone(),
            },
            Some(Cancellation::default()),
        );
        let started = Instant::now();
        assert!(session.next_captured_frame(timeout).unwrap().is_none());
        assert!(started.elapsed() >= timeout);
        let polls = polls.load(Ordering::SeqCst);
        assert!(
            (1..=maximum_polls).contains(&polls),
            "{polls} polls in {timeout:?}"
        );
    }
}

#[derive(Clone)]
struct CountingLayer2(Arc<AtomicUsize>);

impl Layer2Sender for CountingLayer2 {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(packetcraftr_netio::transmit::Submission::start()
            .complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

#[derive(Clone)]
struct CountingLayer3(Arc<AtomicUsize>);

impl Layer3Sender for CountingLayer3 {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(packetcraftr_netio::transmit::Submission::start()
            .complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

#[test]
fn typed_transmission_frames_enforce_mode_and_dispatch_exact_bytes() {
    let bytes = Bytes::from_static(&[1, 2, 3]);
    let layer2_route = materialized(Mode::Layer2);
    let layer3_route = materialized(Mode::Layer3);
    let auto_route = materialized(Mode::Auto);

    assert!(matches!(
        Layer2Frame::try_new(&bytes, &layer3_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer2,
            actual: Mode::Layer3
        })
    ));
    assert!(matches!(
        Layer3Frame::try_new(&bytes, &layer2_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer3,
            actual: Mode::Layer2
        })
    ));
    assert!(matches!(
        Frame::try_new(&bytes, &auto_route),
        Err(Error::UnresolvedLinkMode)
    ));

    let layer2_calls = Arc::new(AtomicUsize::new(0));
    let layer3_calls = Arc::new(AtomicUsize::new(0));
    let dispatch = ModeSender::new(
        CountingLayer2(Arc::clone(&layer2_calls)),
        CountingLayer3(Arc::clone(&layer3_calls)),
    );
    let frame = Frame::try_new(&bytes, &layer2_route).expect("Layer 2 frame");
    assert_eq!(frame.bytes(), &bytes);
    assert_eq!(frame.route(), &layer2_route);
    let report = dispatch.send(frame).expect("fixture send");
    assert_eq!(report.wire_bytes(), &bytes);
    assert_eq!(layer2_calls.load(Ordering::SeqCst), 1);
    assert_eq!(layer3_calls.load(Ordering::SeqCst), 0);

    dispatch
        .send(Frame::try_new(&bytes, &layer3_route).expect("Layer 3 frame"))
        .expect("fixture send");
    assert_eq!(layer3_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn send_reports_validate_counts_bytes_and_provider_timing() {
    let expected = Bytes::from_static(&[1, 2, 3]);
    let submission = packetcraftr_netio::transmit::Submission::start();
    let started = submission.started();
    let report = submission.complete(expected.len(), expected.clone());

    assert_eq!(report.bytes_sent(), expected.len());
    assert_eq!(report.wire_bytes(), &expected);
    assert!(report.timing().is_consistent());
    assert!(report.timing().started().monotonic() >= started.monotonic());
    assert_eq!(report.timing().started().wall_clock(), started.wall_clock());
    assert!(
        report.timing().freshness_marker().monotonic() >= report.timing().started().monotonic()
    );
    assert!(report.validate_exact(&expected).is_ok());

    assert!(matches!(
        Report::committed(expected.len() - 1, expected.clone()).validate_exact(&expected),
        Err(Error::PartialSend {
            expected: 3,
            actual: 2
        })
    ));
    assert!(matches!(
        Report::committed(expected.len(), Bytes::from_static(&[1, 2])).validate_exact(&expected),
        Err(Error::InvalidSendReport {
            bytes_sent: 3,
            wire_bytes: 2
        })
    ));
    assert!(matches!(
        Report::committed(expected.len(), Bytes::from_static(&[3, 2, 1])).validate_exact(&expected),
        Err(Error::InvalidSendEvidence { .. })
    ));
}

#[test]
fn route_model_helpers_cover_neighbor_and_vlan_contracts() {
    let mut plan = planned(Mode::Layer2);
    plan.destination_mac = None;
    assert!(plan.needs_neighbor_resolution());
    plan.lookup_destination = Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)));
    assert!(!plan.needs_neighbor_resolution());
    plan.mode = Mode::Layer3;
    plan.lookup_destination = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
    assert!(!plan.needs_neighbor_resolution());
}

#[test]
fn planner_preserves_explicit_ethernet_destination_for_broadcast() {
    let source = Ipv4Addr::new(10, 23, 0, 2);
    let directed_broadcast = Ipv4Addr::new(10, 23, 0, 255);
    let explicit_mac = MacAddress([0x02, 0, 0, 0, 0, 99]);
    let mut explicit_packet = Packet::new();
    explicit_packet.push(Ethernet {
        destination: explicit_mac.0,
        ..Ethernet::default()
    });
    explicit_packet.push(Ipv4 {
        source,
        destination: directed_broadcast,
        ..Ipv4::default()
    });
    explicit_packet.push(Raw::new(vec![1_u8]));
    let mut explicit_route = decision(Capability::Layer2AndLayer3);
    explicit_route.selected_source = Some(IpAddr::V4(source));
    explicit_route.next_hop = None;
    explicit_route.selection_reason = SelectionReason::Broadcast;
    let explicit = plan_route(
        &explicit_packet,
        None,
        &Options {
            link_mode: Mode::Layer2,
            ..Options::default()
        },
        &routes(Ok(explicit_route)),
    )
    .expect("explicit broadcast envelope plans");
    assert_eq!(explicit.destination_mac, Some(explicit_mac));
    assert_eq!(explicit.neighbor_target, None);
}

#[test]
fn neighbor_options_reject_every_unbounded_value() {
    let defaults = neighbor::Options::default();
    defaults.validate().expect("defaults are valid");

    let invalid = [
        neighbor::Options {
            max_attempts: 0,
            ..defaults.clone()
        },
        neighbor::Options {
            max_attempts: 11,
            ..defaults.clone()
        },
        neighbor::Options {
            attempt_timeout: Duration::ZERO,
            ..defaults.clone()
        },
        neighbor::Options {
            attempt_timeout: Duration::from_secs(31),
            ..defaults.clone()
        },
        neighbor::Options {
            cache_ttl: Duration::ZERO,
            ..defaults.clone()
        },
        neighbor::Options {
            cache_ttl: Duration::from_secs(3_601),
            ..defaults.clone()
        },
        neighbor::Options {
            max_cache_entries: 0,
            ..defaults.clone()
        },
        neighbor::Options {
            max_cache_entries: 65_537,
            ..defaults.clone()
        },
        neighbor::Options {
            snap_length: 127,
            ..defaults.clone()
        },
        neighbor::Options {
            max_capture_queue_frames: 0,
            ..defaults.clone()
        },
    ];

    for options in invalid {
        assert!(matches!(
            options.validate(),
            Err(neighbor::Error::InvalidOptions { .. })
        ));
    }
}
