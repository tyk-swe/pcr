// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr::Client;
use packetcraftr::policy::{DestinationConstraint, Policy};
use packetcraftr::probe::ProbeEndpoint;
use packetcraftr::scan::discovery::{
    Basis, Evidence, Mode, NeighborOutcome, Options, ReasonKind, Scan, State, Unresponsive,
};
use packetcraftr::scan::{self, Reply, Request, Stage, connect};
use packetcraftr::target::{Family, Specification, Target};
use packetcraftr::{ProviderSet, route};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{
    BoundaryError, Classification as ErrorClassification, Classified, Kind,
};
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
use packetcraftr_netio::interface::Id;
use packetcraftr_netio::link::{Capability, Mode as LinkMode};
use packetcraftr_netio::route::{Decision, Provider, Scope, SelectionReason};

use crate::common::responder::{Io, Routes, State as Responder};
use crate::common::{
    self, FixedRoutes, INTERFACE_MAC, NEIGHBOR_MAC, RecordingTransmit, SELECTED_SOURCE,
    ScriptedResolver, ScriptedTcp, Step, Steps,
};

const FIRST: &str = "192.0.2.10";
const SECOND: &str = "192.0.2.11";
const GATEWAY: &str = "192.0.2.1";
const MOVED_GATEWAY: &str = "192.0.2.254";

fn address(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn tcp(port: u16) -> ProbeEndpoint {
    ProbeEndpoint::Tcp { port }
}

fn discovery(mode: Mode, probes: Vec<ProbeEndpoint>) -> Options {
    Options {
        mode,
        probes,
        ..Options::default()
    }
}

fn request(targets: &[&str], endpoints: Vec<ProbeEndpoint>, discovery: Options) -> Request {
    Request {
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: packetcraftr::target::Selection {
            include: targets
                .iter()
                .map(|text| Specification::Target(Target::Address(address(text))))
                .collect(),
            exclude: Vec::new(),
        },
        address_family: Family::Any,
        endpoints,
        discovery,
        attempts: 1,
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        limits: scan::Limits {
            max_duration: Duration::from_secs(3),
            ..Default::default()
        },
        route: route::Options {
            link_mode: LinkMode::Layer3,
            ..Default::default()
        },
        collection: {
            let mut collection = packetcraftr::exchange::Collection::default();
            collection.capture.snap_length = 1500;
            collection
        },
    }
}

fn raw_scan(
    request: Request,
    responder: Responder,
) -> (Result<scan::Aggregate, scan::Error>, usize) {
    let state = Arc::new(Mutex::new(responder));
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(Routes, Io(Arc::clone(&state))),
    );
    let collector = scan::Collector::default();
    let result = client
        .scan(request, collector.clone())
        .and_then(|report| collector.finish(report));
    let sends = state.lock().unwrap().sends;
    (result, sends)
}

fn resets() -> Responder {
    Responder {
        tied_resets: true,
        ..Responder::default()
    }
}

#[test]
fn closed_but_responsive_tcp_is_host_evidence() {
    let (result, sends) = raw_scan(
        request(
            &[FIRST],
            vec![tcp(443)],
            discovery(Mode::Before, vec![tcp(80)]),
        ),
        resets(),
    );
    let report = result.expect("discovery before a scan");
    assert_eq!(sends, 2);

    let host = &report.hosts[0];
    assert_eq!((host.state, host.scan), (State::Responded, Scan::Scanned));
    assert_eq!(host.probes, [0]);
    let reason = &host.reasons[0];
    assert_eq!(reason.kind, ReasonKind::Reply(Reply::TcpReset));
    assert_eq!(
        (reason.kind.evidence(), reason.basis),
        (Evidence::Wire, Basis::Direct)
    );

    // Discovery probes stay out of the endpoints and keep their own stage.
    assert_eq!(report.discovery.len(), 1);
    assert_eq!(report.discovery[0].stage, Stage::Discovery);
    assert_eq!(report.endpoints.len(), 1);
    assert_eq!(report.endpoints[0].port, Some(443));
    assert_eq!(report.endpoints[0].probes[0].sequence, 1);
    assert_eq!(report.endpoints[0].probes[0].stage, Stage::Scan);
}

#[test]
fn udp_discovery_counts_a_port_unreachable_from_the_host() {
    let (result, _) = raw_scan(
        request(
            &[FIRST],
            Vec::new(),
            discovery(Mode::Only, vec![ProbeEndpoint::Udp { port: 53 }]),
        ),
        Responder::default(),
    );
    let host = &result.expect("discovery only").hosts[0];
    assert_eq!(
        (host.state, host.scan),
        (State::Responded, Scan::NotRequested)
    );
    assert_eq!(
        host.reasons[0].kind,
        ReasonKind::Reply(Reply::IcmpPortUnreachable)
    );
}

#[test]
fn silent_hosts_stay_uncertain_and_follow_the_requested_choice() {
    let silent = || Responder {
        suppress_replies: true,
        ..Responder::default()
    };
    let (result, sends) = raw_scan(
        request(
            &[FIRST, SECOND],
            vec![tcp(443)],
            discovery(Mode::Before, vec![tcp(80)]),
        ),
        silent(),
    );
    let report = result.expect("silent discovery");
    assert_eq!(sends, 2, "skipped hosts receive no scan probe");
    assert!(report.endpoints.is_empty());
    for host in &report.hosts {
        assert_eq!((host.state, host.scan), (State::NoResponse, Scan::Skipped));
        assert!(host.reasons.is_empty());
    }

    let mut scan_anyway = request(
        &[FIRST, SECOND],
        vec![tcp(443)],
        discovery(Mode::Before, vec![tcp(80)]),
    );
    scan_anyway.discovery.unresponsive = Unresponsive::Scan;
    let (result, sends) = raw_scan(scan_anyway, silent());
    let report = result.expect("silent discovery with scans");
    assert_eq!(sends, 4);
    assert_eq!(report.endpoints.len(), 2);
    assert!(
        report
            .hosts
            .iter()
            .all(|host| (host.state, host.scan) == (State::NoResponse, Scan::Scanned))
    );
}

#[test]
fn omitted_and_skipped_discovery_send_no_discovery_probe() {
    for (mode, state) in [
        (Mode::Omitted, State::NotRequested),
        (Mode::Skipped, State::Skipped),
    ] {
        let (result, sends) = raw_scan(
            request(&[FIRST], vec![tcp(443)], discovery(mode, Vec::new())),
            resets(),
        );
        let report = result.expect("scan without discovery");
        assert_eq!(sends, 1);
        assert!(report.discovery.is_empty());
        let host = &report.hosts[0];
        assert_eq!((host.state, host.scan), (state, Scan::Scanned));
        assert!(host.reasons.is_empty());
    }
}

#[test]
fn one_budget_covers_discovery_and_the_scan() {
    let mut request = request(
        &[FIRST],
        vec![tcp(443)],
        discovery(Mode::Before, vec![tcp(80)]),
    );
    request.limits.max_probes = 1;
    let (result, sends) = raw_scan(request, resets());
    assert!(matches!(
        result,
        Err(scan::Error::InvalidLimit {
            field: "probes",
            ..
        })
    ));
    assert_eq!(sends, 0);
}

fn layer2_client(
    policy: Policy,
) -> (
    Client<common::FakeProviders<FixedRoutes, RecordingTransmit>>,
    Steps,
) {
    let steps = Steps::default();
    let client = Client::new(
        builtin::registry(),
        policy,
        common::providers(FixedRoutes, RecordingTransmit::new(steps.clone())),
    );
    (client, steps)
}

fn neighbor_only(targets: &[&str]) -> Request {
    let mut request = request(targets, Vec::new(), discovery(Mode::Only, Vec::new()));
    request.discovery.neighbor = true;
    request.route = route::Options::default();
    request
}

fn scan_with<P>(client: &Client<P>, request: Request) -> scan::Aggregate
where
    P: packetcraftr::PacketProviders + packetcraftr::TargetProviders,
{
    let collector = scan::Collector::default();
    client
        .scan(request, collector.clone())
        .and_then(|report| collector.finish(report))
        .expect("neighbor discovery")
}

#[test]
fn neighbor_replies_and_cache_entries_are_distinct_evidence() {
    let (client, steps) = layer2_client(Policy::default());
    let fresh = scan_with(&client, neighbor_only(&[FIRST]));
    assert_eq!(steps.take(), [Step::Neighbor(address(FIRST))]);
    let host = &fresh.hosts[0];
    assert_eq!(host.state, State::Responded);
    let reason = &host.reasons[0];
    assert_eq!(
        (reason.kind, reason.basis, reason.link_address, reason.probe),
        (
            ReasonKind::NeighborReply,
            Basis::Direct,
            Some(NEIGHBOR_MAC),
            None
        )
    );
    assert_eq!(reason.kind.evidence(), Evidence::Wire);

    let cached = scan_with(&client, neighbor_only(&[FIRST]));
    assert!(steps.take().is_empty(), "a cached entry sends nothing");
    let reason = &cached.hosts[0].reasons[0];
    assert_eq!(
        (reason.kind, reason.basis, reason.kind.evidence()),
        (ReasonKind::NeighborCache, Basis::Cached, Evidence::Cache)
    );
    assert_eq!(cached.hosts[0].neighbor.as_ref().unwrap().attempts, 0);
}

#[test]
fn a_neighbor_reply_without_a_capture_time_is_published_untimed() {
    let steps = Steps::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(FixedRoutes, RecordingTransmit::untimed(steps.clone())),
    );
    let report = scan_with(&client, neighbor_only(&[FIRST]));
    assert_eq!(steps.take(), [Step::Neighbor(address(FIRST))]);
    let host = &report.hosts[0];
    let neighbor = host.neighbor.as_ref().expect("neighbor record");
    assert!(
        matches!(
            neighbor.outcome,
            scan::discovery::NeighborOutcome::Resolved(link) if !link.cached
        ),
        "{neighbor:?}"
    );
    assert_eq!(neighbor.observed_at, None, "no settlement time stands in");
    assert_eq!(host.reasons[0].observed_at, None);
}

#[test]
fn a_pipelined_stage_over_its_preparation_limit_sends_no_neighbor_request() {
    let steps = Steps::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(GatewayRoutes, RecordingTransmit::new(steps.clone())),
    );
    let mut request = request(
        &[FIRST, SECOND],
        Vec::new(),
        discovery(Mode::Only, vec![ProbeEndpoint::Icmp]),
    );
    request.route = route::Options {
        link_mode: LinkMode::Layer2,
        ..route::Options::default()
    };
    request.max_in_flight = 2;
    request.limits.max_prepared_bytes = 64;
    let result = client.scan(request, scan::Collector::default());
    assert!(
        matches!(result, Err(scan::Error::PipelineExecution { .. })),
        "{result:?}"
    );
    assert!(
        steps.take().is_empty(),
        "the preparation limit precedes the gateway's request"
    );
}

#[test]
fn explicit_neighbor_discovery_waits_for_the_preparation_limit() {
    // 64 bytes cannot hold the batch descriptions; 4096 hold them but not
    // the routes and packets the pipeline itself charges.
    for max_prepared_bytes in [64, 4096] {
        let (client, steps) = layer2_client(Policy::default());
        let mut request = neighbor_only(&[FIRST, SECOND]);
        request.discovery.probes = vec![ProbeEndpoint::Icmp];
        request.max_in_flight = 2;
        request.limits.max_prepared_bytes = max_prepared_bytes;
        let result = client.scan(request, scan::Collector::default());
        assert!(
            matches!(result, Err(scan::Error::PipelineExecution { .. })),
            "{max_prepared_bytes}: {result:?}"
        );
        assert!(
            steps.take().is_empty(),
            "{max_prepared_bytes}: the preparation limit precedes the targets' own requests"
        );
    }
}

fn pipeline_failure(error: &scan::Error) -> Option<&scan::PipelineFailure> {
    use std::error::Error as _;
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(failure) = error.downcast_ref::<scan::PipelineFailure>() {
            return Some(failure);
        }
        source = error.source();
    }
    None
}

#[test]
fn a_pipeline_failure_reports_the_traffic_before_it() {
    let steps = Steps::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(GatewayRoutes, RecordingTransmit::new(steps.clone())),
    );
    let mut request = request(
        &[FIRST],
        Vec::new(),
        discovery(Mode::Only, vec![ProbeEndpoint::Icmp]),
    );
    request.route = route::Options {
        link_mode: LinkMode::Layer2,
        ..route::Options::default()
    };
    request.max_in_flight = 2;
    let refuse_sends = |event: scan::Event| match event {
        scan::Event::Sent(_) => Err(BoundaryError::new(
            "fixture sink failed",
            ErrorClassification::new("io.fixture_sink", Kind::Io, None),
            Vec::new(),
        )),
        _ => Ok(()),
    };
    let error = client
        .scan(request, refuse_sends)
        .expect_err("the sink refuses the probe's send");
    let failure = pipeline_failure(&error).expect("the pipeline failed");
    assert!(
        matches!(
            steps.take().as_slice(),
            [Step::Neighbor(_), Step::Transmit(_)]
        ),
        "the gateway's request precedes the probe"
    );
    assert_eq!(failure.stats.packets_attempted, 2, "{:?}", failure.stats);
    assert_eq!(failure.stats.packets_completed, 2, "{:?}", failure.stats);
}

#[test]
fn one_link_address_for_several_targets_is_a_possible_proxy() {
    let (client, _) = layer2_client(Policy::default());
    let report = scan_with(&client, neighbor_only(&[FIRST, SECOND]));
    for host in &report.hosts {
        assert_eq!(host.reasons[0].basis, Basis::PossibleProxy);
        assert_eq!(host.reasons[0].link_address, Some(NEIGHBOR_MAC));
    }
}

#[derive(Clone, Copy)]
struct GatewayRoutes;

impl Provider for GatewayRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Infallible> {
        Ok(through(GATEWAY))
    }
}

/// Routes the first lookup through `GATEWAY` and every later one through
/// another gateway.
/// Routes through `GATEWAY` for the first `.1` lookups, then through
/// `MOVED_GATEWAY`.
struct MovingGateway(Arc<AtomicUsize>, usize);

impl Provider for MovingGateway {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Infallible> {
        let stable = self.0.fetch_add(1, Ordering::Relaxed) < self.1;
        Ok(through(if stable { GATEWAY } else { MOVED_GATEWAY }))
    }
}

fn through(gateway: &str) -> Decision {
    Decision {
        interface: Id {
            name: "fixture0".to_owned(),
            index: 1,
        },
        source_mac: Some(INTERFACE_MAC),
        selected_source: Some(IpAddr::V4(SELECTED_SOURCE)),
        preferred_source: None,
        next_hop: Some(address(gateway)),
        selection_reason: SelectionReason::Gateway,
        destination_scope: Scope::Global,
        mtu: 1_500,
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    }
}

#[test]
fn neighbor_discovery_of_a_multicast_target_needs_no_reply_sized_capture() {
    let (client, steps) = layer2_client(Policy {
        allow_public_destinations: true,
        ..Policy::default()
    });
    let mut request = neighbor_only(&["233.252.0.1"]);
    // Too short for a neighbor reply, which a multicast target is never sent.
    request.collection.capture.snap_length = 64;
    let report = scan_with(&client, request);
    assert!(steps.take().is_empty());
    assert_eq!(
        report.hosts[0]
            .neighbor
            .as_ref()
            .map(|neighbor| neighbor.outcome),
        Some(NeighborOutcome::NotApplicable)
    );
}

#[test]
fn a_routed_gateway_answer_is_not_host_evidence() {
    let steps = Steps::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(GatewayRoutes, RecordingTransmit::new(steps.clone())),
    );
    let alone = scan_with(&client, neighbor_only(&[FIRST]));
    // The gateway is not a selected target, so it is sent nothing.
    assert!(steps.take().is_empty());
    let host = &alone.hosts[0];
    assert_eq!(
        (host.state, host.scan),
        (State::NoResponse, Scan::NotRequested)
    );
    assert!(host.reasons.is_empty());
    let neighbor = host.neighbor.as_ref().unwrap();
    let NeighborOutcome::Routed(next_hop) = &neighbor.outcome else {
        panic!("the target is reached through its gateway");
    };
    assert_eq!(
        (next_hop.address, next_hop.link, neighbor.attempts),
        (address(GATEWAY), None, 0)
    );

    // A gateway selected as a target answers for itself; the routed target
    // reports that entry only as its cached next hop.
    let both = scan_with(&client, neighbor_only(&[GATEWAY, FIRST]));
    assert_eq!(steps.take(), [Step::Neighbor(address(GATEWAY))]);
    let [gateway, routed] = &both.hosts[..] else {
        panic!("one record per target");
    };
    assert_eq!(gateway.state, State::Responded);
    assert_eq!(gateway.reasons[0].basis, Basis::Direct);
    assert_eq!(routed.state, State::NoResponse);
    assert!(routed.reasons.is_empty());
    let Some(NeighborOutcome::Routed(next_hop)) = routed.neighbor.as_ref().map(|n| &n.outcome)
    else {
        panic!("the target is reached through its gateway");
    };
    let link = next_hop.link.unwrap();
    assert_eq!((link.address, link.cached), (NEIGHBOR_MAC, true));
}

#[test]
fn unauthorized_targets_draw_no_neighbor_request() {
    let (client, steps) = layer2_client(Policy {
        allowed_destinations: vec![DestinationConstraint::Exact(address(SECOND))],
        ..Policy::default()
    });
    let collector = scan::Collector::default();
    assert!(matches!(
        client.scan(neighbor_only(&[FIRST]), collector),
        Err(scan::Error::Authorization(_))
    ));
    assert!(steps.take().is_empty());
}

#[test]
fn a_route_moved_after_its_stage_resolved_sends_no_unaccounted_neighbor_request() {
    let steps = Steps::default();
    let lookups = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(
            MovingGateway(Arc::clone(&lookups), 1),
            RecordingTransmit::new(steps.clone()),
        ),
    );
    let mut request = request(
        &[FIRST],
        Vec::new(),
        discovery(Mode::Only, vec![ProbeEndpoint::Icmp]),
    );
    request.route = route::Options {
        link_mode: LinkMode::Layer2,
        ..route::Options::default()
    };
    let error = client
        .scan(request, scan::Collector::default())
        .expect_err("the probe's route needs a neighbor its stage never resolved");
    assert_eq!(error.classification().code, "io.route_changed", "{error}");
    assert!(lookups.load(Ordering::Relaxed) > 1);
    // Only the stage's own, accounted request reached the wire.
    assert_eq!(steps.take(), [Step::Neighbor(address(GATEWAY))]);
}

#[test]
fn a_route_moved_between_stages_sends_no_second_neighbor_request() {
    let scan = |stable| {
        let steps = Steps::default();
        let client = Client::new(
            builtin::registry(),
            Policy::default(),
            common::providers(
                MovingGateway(Arc::new(AtomicUsize::new(0)), stable),
                RecordingTransmit::new(steps.clone()),
            ),
        );
        let mut request = request(
            &[FIRST],
            vec![tcp(443)],
            discovery(Mode::Before, vec![ProbeEndpoint::Icmp]),
        );
        request.discovery.unresponsive = Unresponsive::Scan;
        request.route = route::Options {
            link_mode: LinkMode::Layer2,
            ..route::Options::default()
        };
        (
            client.scan(request, scan::Collector::default()),
            steps.take(),
        )
    };

    let (stable, steps) = scan(usize::MAX);
    assert_eq!(
        stable
            .expect("a stable route scans")
            .stats
            .packets_attempted,
        3
    );
    assert!(matches!(
        steps.as_slice(),
        [Step::Neighbor(gateway), Step::Transmit(_), Step::Transmit(_)] if *gateway == address(GATEWAY)
    ));
    // The discovery stage's lookups see the first gateway; the scan stage's
    // see another, whose request the plan never budgeted.
    let (moved, steps) = scan(2);
    let error = moved.expect_err("the scan stage's route needs a second neighbor");
    assert_eq!(error.classification().code, "io.route_changed", "{error}");
    assert!(
        matches!(
            steps.as_slice(),
            [Step::Neighbor(gateway), Step::Transmit(_)] if *gateway == address(GATEWAY)
        ),
        "{steps:?}"
    );
}

#[test]
fn a_probe_through_a_denied_gateway_sends_no_neighbor_request() {
    let steps = Steps::default();
    let client = |allowed: &[&str]| {
        Client::new(
            builtin::registry(),
            Policy {
                allowed_destinations: allowed
                    .iter()
                    .map(|text| DestinationConstraint::Exact(address(text)))
                    .collect(),
                ..Policy::default()
            },
            common::providers(GatewayRoutes, RecordingTransmit::new(steps.clone())),
        )
    };
    let mut request = request(
        &[FIRST],
        Vec::new(),
        discovery(Mode::Only, vec![ProbeEndpoint::Icmp]),
    );
    request.route = route::Options {
        link_mode: LinkMode::Layer2,
        ..route::Options::default()
    };
    let error = client(&[FIRST])
        .scan(request.clone(), scan::Collector::default())
        .expect_err("the policy denies the gateway the probe resolves");
    assert_eq!(
        error.classification().code,
        "policy.destination_not_allowed",
        "{error:?}"
    );
    assert!(steps.take().is_empty());

    client(&[FIRST, GATEWAY])
        .scan(request, scan::Collector::default())
        .expect("an authorized gateway is resolved");
    assert!(matches!(
        steps.take().as_slice(),
        [Step::Neighbor(gateway), Step::Transmit(_)] if *gateway == address(GATEWAY)
    ));
}

#[test]
fn a_stage_resolves_its_gateway_before_any_capture_and_counts_the_request() {
    let steps = Steps::default();
    let io = RecordingTransmit::new(steps.clone());
    let client = Client::new(
        builtin::registry(),
        Policy {
            allowed_destinations: [FIRST, SECOND, GATEWAY]
                .iter()
                .map(|text| DestinationConstraint::Exact(address(text)))
                .collect(),
            ..Policy::default()
        },
        common::providers(GatewayRoutes, io.clone()),
    );
    let mut request = request(
        &[FIRST, SECOND],
        Vec::new(),
        discovery(Mode::Only, vec![ProbeEndpoint::Icmp]),
    );
    request.route = route::Options {
        link_mode: LinkMode::Layer2,
        ..route::Options::default()
    };
    request.max_in_flight = 2;
    let report = client
        .scan(request, scan::Collector::default())
        .expect("the gateway is authorized");

    let steps = steps.take();
    assert!(
        matches!(
            steps.as_slice(),
            [Step::Neighbor(gateway), Step::Transmit(_), Step::Transmit(_)]
                if *gateway == address(GATEWAY)
        ),
        "{steps:?}"
    );
    assert_eq!(io.peak_armed(), 1, "the gateway's capture ended first");
    assert_eq!(report.stats.packets_attempted, 3);
    assert_eq!(report.stats.packets_completed, 3);
}

#[test]
fn a_client_bounded_by_a_scan_paces_a_neighbor_request_like_a_probe() {
    let send_echo = |client: &Client<_, common::clock::VirtualClock>, plan: &route::Options| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            destination: FIRST.parse().unwrap(),
            ..Ipv4::default()
        });
        packet.push(Icmpv4 {
            icmp_type: 8,
            ..Icmpv4::default()
        });
        client
            .send(
                packetcraftr::send::Request::packet(
                    packet,
                    packetcraftr::send::Options {
                        plan: plan.clone(),
                        ..packetcraftr::send::Options::default()
                    },
                ),
                packetcraftr::send::Collector::default(),
            )
            .expect("the gateway answers");
    };
    let mut scan = request(
        &[FIRST],
        Vec::new(),
        discovery(Mode::Only, vec![ProbeEndpoint::Icmp]),
    );
    scan.route = route::Options {
        link_mode: LinkMode::Layer2,
        ..route::Options::default()
    };
    scan.probes_per_second = Some(10);

    for bounded in [false, true] {
        let steps = Steps::default();
        let clock = common::clock::VirtualClock::default();
        let client = Client::new(
            builtin::registry(),
            Policy::default(),
            common::providers(GatewayRoutes, RecordingTransmit::new(steps.clone())),
        )
        .with_clock(clock.clone());
        let client = if bounded {
            client
                .with_scan_neighbors(&scan)
                .expect("the scan's evidence limits hold a reply")
        } else {
            client
        };
        send_echo(&client, &scan.route);
        send_echo(&client, &scan.route);
        assert!(
            matches!(
                steps.take().as_slice(),
                [Step::Neighbor(_), Step::Transmit(_), Step::Transmit(_)]
            ),
            "the second packet reuses the answer"
        );
        let expected: &[Duration] = if bounded {
            &[Duration::from_millis(100)]
        } else {
            &[]
        };
        assert_eq!(
            clock.delays(),
            expected,
            "only a scan's bounds space the packet from its fresh request"
        );
    }
}

#[test]
fn a_client_bounded_by_a_scan_sends_one_request_to_a_silent_gateway() {
    let steps = Steps::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(GatewayRoutes, RecordingTransmit::silent(steps.clone())),
    );
    let mut scan = request(
        &[FIRST],
        Vec::new(),
        discovery(Mode::Only, vec![ProbeEndpoint::Icmp]),
    );
    scan.route = route::Options {
        link_mode: LinkMode::Layer2,
        ..route::Options::default()
    };
    scan.timeout = Duration::from_millis(20);
    let client = client
        .with_scan_neighbors(&scan)
        .expect("the scan's evidence limits hold a reply");

    let mut packet = Packet::new();
    packet.push(Ipv4 {
        destination: FIRST.parse().unwrap(),
        ..Ipv4::default()
    });
    packet.push(Icmpv4 {
        icmp_type: 8,
        ..Icmpv4::default()
    });
    client
        .send(
            packetcraftr::send::Request::packet(
                packet,
                packetcraftr::send::Options {
                    plan: scan.route.clone(),
                    ..packetcraftr::send::Options::default()
                },
            ),
            packetcraftr::send::Collector::default(),
        )
        .expect_err("the gateway never answers");
    assert_eq!(
        steps.take(),
        vec![Step::Neighbor(address(GATEWAY))],
        "one request within the scan's timeout, not the resolver's default attempts"
    );
}

#[test]
fn a_client_authorizing_neighbor_requests_denies_any_workflows_gateway() {
    let steps = Steps::default();
    let client = || {
        Client::new(
            builtin::registry(),
            Policy {
                allowed_destinations: vec![DestinationConstraint::Exact(address(FIRST))],
                ..Policy::default()
            },
            common::providers(GatewayRoutes, RecordingTransmit::new(steps.clone())),
        )
    };
    let send = |client: &Client<common::FakeProviders<GatewayRoutes, RecordingTransmit>>| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            destination: FIRST.parse().unwrap(),
            ..Ipv4::default()
        });
        packet.push(Icmpv4 {
            icmp_type: 8,
            ..Icmpv4::default()
        });
        client.send(
            packetcraftr::send::Request::packet(
                packet,
                packetcraftr::send::Options {
                    plan: route::Options {
                        link_mode: LinkMode::Layer2,
                        ..route::Options::default()
                    },
                    ..packetcraftr::send::Options::default()
                },
            ),
            packetcraftr::send::Collector::default(),
        )
    };

    let error = send(&client().with_neighbor_request_authorization())
        .expect_err("the policy denies the gateway the send resolves");
    assert_eq!(
        error.classification().code,
        "policy.destination_not_allowed",
        "{error:?}"
    );
    assert!(steps.take().is_empty());

    send(&client()).expect("other clients resolve the gateway as before");
    assert!(matches!(
        steps.take().as_slice(),
        [Step::Neighbor(gateway), Step::Transmit(_)] if *gateway == address(GATEWAY)
    ));
}

fn connect_scan(request: Request) -> (Result<connect::Aggregate, scan::Error>, Vec<SocketAddr>) {
    let tcp = ScriptedTcp::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(tcp.clone(), ScriptedResolver::default()),
    );
    let collector = connect::Collector::default();
    let result = client
        .scan_connect(request, collector.clone())
        .and_then(|report| collector.finish(report));
    let connects = tcp
        .steps
        .take()
        .into_iter()
        .filter_map(|step| match step {
            Step::Connect(endpoint) => Some(endpoint),
            _ => None,
        })
        .collect();
    (result, connects)
}

fn socket_request(discovery: Options) -> Request {
    let mut request = request(&[FIRST], vec![tcp(443)], discovery);
    request.route = route::Options::default();
    request
}

#[test]
fn ordinary_sockets_publish_socket_observations() {
    let (result, connects) = connect_scan(socket_request(discovery(Mode::Before, vec![tcp(22)])));
    let report = result.expect("connect discovery");
    assert_eq!(
        connects,
        [
            SocketAddr::new(address(FIRST), 22),
            SocketAddr::new(address(FIRST), 443),
        ]
    );
    let host = &report.report.hosts[0];
    assert_eq!((host.state, host.scan), (State::Responded, Scan::Scanned));
    let reason = &host.reasons[0];
    assert_eq!(
        (reason.kind, reason.kind.evidence(), reason.probe),
        (ReasonKind::Refused, Evidence::Socket, Some(0))
    );
    assert_eq!(report.discovery.len(), 1);
    assert_eq!(report.endpoints.len(), 1);
    assert_eq!(report.endpoints[0].probes[0].sequence, 1);
}

#[test]
fn ordinary_sockets_refuse_raw_discovery_probes_before_connecting() {
    for options in [
        discovery(Mode::Before, vec![ProbeEndpoint::Icmp]),
        discovery(Mode::Before, vec![ProbeEndpoint::Udp { port: 53 }]),
        Options {
            neighbor: true,
            ..discovery(Mode::Before, Vec::new())
        },
    ] {
        let (result, connects) = connect_scan(socket_request(options));
        assert!(matches!(result, Err(scan::Error::MethodProbe { .. })));
        assert!(connects.is_empty());
    }
}

#[test]
fn a_silent_next_hop_leaves_its_host_unresponsive_and_unscanned() {
    for (mode, endpoints, scan) in [
        (Mode::Only, Vec::new(), Scan::NotRequested),
        (Mode::Before, vec![tcp(443)], Scan::Skipped),
    ] {
        let steps = Steps::default();
        let client = Client::new(
            builtin::registry(),
            Policy::default(),
            common::providers(FixedRoutes, RecordingTransmit::silent(steps.clone())),
        );
        let mut request = request(
            &[FIRST, SECOND],
            endpoints,
            discovery(mode, vec![ProbeEndpoint::Icmp]),
        );
        if mode == Mode::Before {
            // Even a request that scans unresponsive hosts cannot frame a
            // probe for a target whose next hop never answered.
            request.discovery.unresponsive = Unresponsive::Scan;
        }
        request.route = route::Options {
            link_mode: LinkMode::Layer2,
            ..route::Options::default()
        };
        let report = client
            .scan(request, scan::Collector::default())
            .expect("a silent next hop ends its host's discovery, not the scan");
        assert_eq!(
            steps.take(),
            [
                Step::Neighbor(address(FIRST)),
                Step::Neighbor(address(SECOND))
            ],
            "{mode:?}"
        );
        assert_eq!(report.stats.packets_attempted, 2, "{mode:?}");
        for host in &report.hosts {
            assert_eq!(host.state, State::NoResponse, "{mode:?}");
            assert_eq!(host.scan, scan, "{mode:?}");
        }
    }
}
