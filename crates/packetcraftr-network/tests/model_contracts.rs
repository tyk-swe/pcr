// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_network::interface::Id as InterfaceId;
use packetcraftr_network::{
    Error,
    capture::{self, Provider as _, Session as _},
    link::{Capability, MacAddress, Mode},
    neighbor,
    route::{
        Decision, Error as PlanError, Materialized, Options, Plan, Provider, Scope,
        SelectionReason, plan as plan_route,
    },
    transmit::{
        Dispatch, Frame, Layer2Frame, Layer2Sender, Layer3Frame, Layer3Sender, Report, Sender,
    },
};
use packetcraftr_packet::protocol::{link::Ethernet, network::Ipv4};
use packetcraftr_packet::{Packet, layer::Raw};
use packetcraftr_packet::{
    error::{Classified, Kind},
    frame::{Frame as CaptureFrame, LinkType},
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
    lookup_calls: &'static AtomicUsize,
    interface_calls: &'static AtomicUsize,
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

static LOOKUP_CALLS: AtomicUsize = AtomicUsize::new(0);
static INTERFACE_CALLS: AtomicUsize = AtomicUsize::new(0);

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
        selected_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
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
    LOOKUP_CALLS.store(0, Ordering::SeqCst);
    INTERFACE_CALLS.store(0, Ordering::SeqCst);
    Routes {
        interface_decision: decision.clone().map(Some),
        decision,
        lookup_calls: &LOOKUP_CALLS,
        interface_calls: &INTERFACE_CALLS,
    }
}

fn planned(mode: Mode) -> Plan {
    Plan {
        route: decision(Capability::Layer2And3),
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
                max_frames: capture::DEFAULT_CAPTURE_QUEUE_FRAMES + 1,
                ..defaults
            },
        ),
        (
            "max_bytes",
            capture::Limits {
                max_bytes: capture::DEFAULT_CAPTURE_QUEUE_BYTES + 1,
                ..defaults
            },
        ),
        (
            "snap_length",
            capture::Limits {
                snap_length: packetcraftr_packet::frame::DEFAULT_SIZE_LIMIT + 1,
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
    assert!(!complete.has_loss());
    assert_eq!(complete.evidence_loss_error(), None);
    assert_eq!(complete.validate().expect("complete statistics"), complete);

    let receiver_loss = capture::Statistics {
        dropped_frames: 3,
        dropped_bytes: 30,
        receiver_dropped_frames: 2,
        ..capture::Statistics::default()
    };
    assert!(receiver_loss.has_loss());
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
fn captured_frame_constructors_preserve_or_omit_monotonic_ingress() {
    let ingress = Instant::now();
    let frame = CaptureFrame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![1_u8])
        .expect("fixture frame");
    let captured = capture::Captured::new(frame.clone(), ingress);
    assert_eq!(captured.frame, frame);
    assert_eq!(captured.received_at, Some(ingress));

    let unknown = capture::Captured::without_ingress_time(frame.clone());
    assert_eq!(unknown.frame, frame);
    assert_eq!(unknown.received_at, None);

    let explicit = capture::Captured::with_ingress_time(frame.clone(), None);
    assert_eq!(explicit.frame, frame);
    assert_eq!(explicit.received_at, None);
}

struct NoCapture;

impl capture::Provider for NoCapture {
    type Capture = EmptySession;

    fn arm_capture(&self, _route: &Plan, _limits: capture::Limits) -> Result<Self::Capture, Error> {
        Ok(EmptySession)
    }
}

#[derive(Debug)]
struct EmptySession;

impl capture::Session for EmptySession {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<capture::Captured>, Error> {
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
fn capture_provider_default_filter_fails_closed_and_session_is_owned() {
    let error = NoCapture
        .arm_capture_with_filter(&planned(Mode::Layer2), capture::Limits::default(), "udp")
        .expect_err("providers must explicitly support native filtering");
    assert!(matches!(error, Error::Unsupported { .. }));

    let mut session = NoCapture
        .arm_capture(&planned(Mode::Layer2), capture::Limits::default())
        .expect("fixture session");
    session
        .wait_ready(Duration::ZERO)
        .expect("fixture is immediately ready");
    assert!(
        session
            .next_captured_frame(Duration::ZERO)
            .expect("fixture read")
            .is_none()
    );
    assert_eq!(session.statistics(), capture::Statistics::default());
    session.shutdown().expect("fixture cleanup");
}

#[derive(Clone)]
struct CountingLayer2(Arc<AtomicUsize>);

impl Layer2Sender for CountingLayer2 {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(packetcraftr_network::transmit::Submission::start()
            .complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

#[derive(Clone)]
struct CountingLayer3(Arc<AtomicUsize>);

impl Layer3Sender for CountingLayer3 {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(packetcraftr_network::transmit::Submission::start()
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
    let dispatch = Dispatch::new(
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
fn route_model_helpers_cover_neighbor_and_vlan_contracts() {
    assert_eq!(
        MacAddress([0, 1, 2, 0xab, 0xcd, 0xef]).to_string(),
        "00:01:02:ab:cd:ef"
    );
    assert_eq!(neighbor::VlanKind::Ieee8021Q.ether_type(), 0x8100);
    assert_eq!(neighbor::VlanKind::Ieee8021Ad.ether_type(), 0x88a8);

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
fn neighbor_options_reject_every_unbounded_configuration() {
    let defaults = neighbor::Options::default();
    assert_eq!(defaults.clone().validate().expect("defaults"), defaults);

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
            Err(neighbor::Error::InvalidConfiguration { .. })
        ));
    }
}

#[test]
fn planner_rejects_invalid_input_before_route_lookup() {
    let provider = routes(Ok(decision(Capability::Layer2And3)));
    let raw = {
        let mut packet = Packet::new();
        packet.push(Raw::new(vec![1_u8]));
        packet
    };

    assert!(matches!(
        plan_route(
            &raw,
            None,
            &Options {
                link_mode: Mode::Layer3,
                ..Options::default()
            },
            &provider
        ),
        Err(PlanError::MissingDestination)
    ));
    assert_eq!(LOOKUP_CALLS.load(Ordering::SeqCst), 0);

    assert!(matches!(
        plan_route(
            &raw,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
            &Options {
                preferred_source: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                ..Options::default()
            },
            &provider
        ),
        Err(PlanError::PreferredSourceFamilyMismatch { .. })
    ));
    assert_eq!(LOOKUP_CALLS.load(Ordering::SeqCst), 0);

    let mut ethernet = Packet::new();
    ethernet.push(Ethernet {
        destination: [0x02, 0, 0, 0, 0, 9],
        ..Ethernet::default()
    });
    ethernet.push(Raw::new(vec![1_u8]));
    assert!(matches!(
        plan_route(
            &ethernet,
            None,
            &Options {
                link_mode: Mode::Layer3,
                ..Options::default()
            },
            &provider
        ),
        Err(PlanError::EthernetInLayer3)
    ));
    assert_eq!(LOOKUP_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
fn planner_maps_provider_failures_and_contract_mismatches() {
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![1_u8]));
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

    let error = plan_route(
        &packet,
        Some(destination),
        &Options::default(),
        &routes(Err(RouteFailure)),
    )
    .expect_err("lookup failure must be typed");
    assert!(matches!(
        error,
        PlanError::RouteLookup {
            destination: actual,
            failure,
            ..
        } if actual == destination && failure.code == "io.route"
    ));

    let mut wrong = decision(Capability::Layer2And3);
    wrong.interface = InterfaceId {
        name: "other0".to_owned(),
        index: 8,
    };
    let requested = interface();
    assert!(matches!(
        plan_route(
            &packet,
            Some(destination),
            &Options {
                interface: Some(requested),
                ..Options::default()
            },
            &routes(Ok(wrong))
        ),
        Err(PlanError::InterfaceMismatch { .. })
    ));

    assert!(matches!(
        plan_route(
            &packet,
            Some(destination),
            &Options {
                preferred_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 77))),
                ..Options::default()
            },
            &routes(Ok(decision(Capability::Layer2And3)))
        ),
        Err(PlanError::PreferredSourceNotSelected { .. })
    ));
}

#[test]
fn planner_selects_auto_layer3_for_ip_root_and_enforces_capability() {
    let destination = Ipv4Addr::new(10, 0, 0, 9);
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(10, 0, 0, 2),
        destination,
        ..Ipv4::default()
    });
    packet.push(Raw::new(vec![1_u8]));

    let plan = plan_route(
        &packet,
        None,
        &Options::default(),
        &routes(Ok(decision(Capability::Layer2And3))),
    )
    .expect("IP root with Layer 3 capability must plan");
    assert_eq!(plan.mode, Mode::Layer3);
    assert_eq!(plan.lookup_destination, Some(IpAddr::V4(destination)));
    assert_eq!(
        plan.packet_source,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
    );

    assert!(matches!(
        plan_route(
            &packet,
            None,
            &Options {
                link_mode: Mode::Layer3,
                ..Options::default()
            },
            &routes(Ok(decision(Capability::Layer2)))
        ),
        Err(PlanError::Layer3Unsupported)
    ));

    let mut layer3_only = decision(Capability::Layer3);
    layer3_only.link_type = LinkType::RAW;
    let mut ethernet = Packet::new();
    ethernet.push(Ethernet {
        destination: [0x02, 0, 0, 0, 0, 9],
        ..Ethernet::default()
    });
    ethernet.push(Raw::new(vec![1_u8]));
    assert!(matches!(
        plan_route(
            &ethernet,
            None,
            &Options {
                link_mode: Mode::Layer2,
                interface: Some(interface()),
                preferred_source: None,
            },
            &Routes {
                decision: Ok(layer3_only.clone()),
                interface_decision: Ok(Some(layer3_only)),
                lookup_calls: &LOOKUP_CALLS,
                interface_calls: &INTERFACE_CALLS,
            }
        ),
        Err(PlanError::Layer2Unsupported)
    ));
}

struct DefaultRouteProvider;

impl Provider for DefaultRouteProvider {
    type Error = RouteFailure;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        Ok(decision(Capability::Layer2And3))
    }
}

#[test]
fn route_provider_defaults_are_passive_and_have_stable_classification() {
    assert_eq!(
        DefaultRouteProvider
            .lookup_interface(&interface())
            .expect("default interface lookup"),
        None
    );
    let classification = DefaultRouteProvider.classify_error(&RouteFailure);
    assert_eq!(classification.code, "io.route");
    assert_eq!(classification.kind, Kind::Io);
}

#[test]
fn live_io_errors_expose_stable_failure_classes() {
    let cases = [
        (
            Error::Unsupported {
                message: "fixture".to_owned(),
            },
            "capability.unsupported",
            Kind::Capability,
        ),
        (
            Error::PartialSend {
                expected: 2,
                actual: 1,
            },
            "io.partial_send",
            Kind::Io,
        ),
        (
            Error::InvalidCaptureTimeout {
                timeout: Duration::ZERO,
                maximum: capture::MAX_TIMEOUT,
            },
            "cli.capture_timeout",
            Kind::Cli,
        ),
        (
            Error::InvalidTransmissionFrame {
                message: "fixture".to_owned(),
            },
            "packet.transmission_frame",
            Kind::Packet,
        ),
        (
            Error::UnresolvedLinkMode,
            "internal.live_io_invariant",
            Kind::Internal,
        ),
    ];

    for (error, code, kind) in cases {
        let classification = error.classification();
        assert_eq!(classification.code, code);
        assert_eq!(classification.kind, kind);
        assert!(classification.remediation.is_some());
        assert!(!error.to_string().is_empty());
    }
}
