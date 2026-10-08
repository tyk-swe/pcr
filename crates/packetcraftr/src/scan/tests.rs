// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use super::Error;
use crate::probe::test_support::private_policy;
use crate::runtime::Runtime;
use crate::test_support::decoded_packet;
use packetcraftr_core::protocol::{
    network::{Icmpv4, Ipv4, Ipv6},
    transport::Tcp,
};
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic, packet::Packet};

use super::engine;
use super::error::Probes;
use super::executor::{PipelineEvent, PipelineOptions, Pipelined};
use super::plan::packet::probe_packet;
use super::{Aggregate, Collector, Event, Limits, Probe, Report, Request};
use crate::Sink;
use crate::clock::Clock;
use crate::execution::Admission;
use crate::execution::{Errors as _, Executor, publisher};
use crate::policy::Authorizer;
use crate::probe::Batch;
use crate::probe::Evidence;
use crate::target::ResolveTarget;
use crate::target::Target;
use crate::test_support::{AddressListAuthorizer, Call, NoopClock, RejectingExecutor};
use crate::{Stats, target::Family};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::registry::Registry;

struct Serial<'e, E>(&'e mut E);

impl<E: Executor<Batch<Probe>>> Executor<Batch<Probe>> for Serial<'_, E> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        self.0.execute(batch)
    }
}

impl<E: Executor<Batch<Probe>>> Pipelined for Serial<'_, E> {
    fn execute_pipeline(
        &mut self,
        _batches: &[Batch<Probe>],
        _options: PipelineOptions,
        _emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        unreachable!("serial fixtures run one probe in flight")
    }

    fn resolve_neighbor(
        &mut self,
        _target: &crate::target::SelectedAddress,
        _timeout: Duration,
        _deadline: &Deadline,
    ) -> Result<(super::discovery::Neighbor, Stats), BoundaryError> {
        unreachable!("serial fixtures select no neighbor discovery")
    }
}

/// Answers neighbor requests from a script, one outcome per call.
#[derive(Default)]
struct ScriptedNeighbors {
    outcomes: std::collections::VecDeque<super::discovery::NeighborOutcome>,
    calls: Vec<IpAddr>,
}

impl Executor<Batch<Probe>> for ScriptedNeighbors {
    fn execute(&mut self, _batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        unreachable!("neighbor-only discovery sends no probe")
    }
}

impl Pipelined for ScriptedNeighbors {
    fn execute_pipeline(
        &mut self,
        _batches: &[Batch<Probe>],
        _options: PipelineOptions,
        _emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        unreachable!("neighbor-only discovery sends no probe")
    }

    fn resolve_neighbor(
        &mut self,
        target: &crate::target::SelectedAddress,
        _timeout: Duration,
        _deadline: &Deadline,
    ) -> Result<(super::discovery::Neighbor, Stats), BoundaryError> {
        use super::discovery::NeighborOutcome;
        self.calls.push(target.address);
        let outcome = self.outcomes.pop_front().expect("a scripted outcome");
        let attempts = u32::from(!matches!(outcome, NeighborOutcome::Routed(_)));
        let stats = Stats {
            packets_attempted: u64::from(attempts),
            packets_completed: u64::from(attempts),
            bytes: 42 * u64::from(attempts),
            ..Stats::default()
        };
        let neighbor = super::discovery::Neighbor {
            outcome,
            interface: fixture_interface(),
            attempts,
            observed_at: Some(UNIX_EPOCH),
        };
        Ok((neighbor, stats))
    }
}

fn fixture_interface() -> packetcraftr_netio::interface::Id {
    packetcraftr_netio::interface::Id {
        name: "fixture0".to_owned(),
        index: 1,
    }
}

fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<Aggregate, Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Batch<Probe>>,
    C: Clock,
{
    let collector = Collector::default();
    let mut sink = collector.clone();
    let report = engine::run(
        request,
        authorizer,
        registry,
        &mut Serial(executor),
        clock,
        &mut Deadline::new(request.limits.max_duration),
        |event, _| {
            sink.publish(event)
                .map_err(|source| Error::Output { source })
        },
    )?;
    collector.finish(report)
}

fn run_with_events<A, E, C, S>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    sink: S,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Batch<Probe>>,
    C: Clock,
    S: Sink<Event, Ack = ()>,
{
    let publish = publisher(
        runtime,
        sink,
        |error| Probes.duration_limit(0, error),
        |source| Error::Output { source },
    )?;
    engine::run(
        request,
        authorizer,
        registry,
        &mut Serial(executor),
        clock,
        &mut Deadline::new(request.limits.max_duration),
        publish,
    )
}

fn tcp_scan_request(target: Target) -> Request {
    Request {
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: target.into(),
        address_family: Family::Any,
        endpoints: vec![crate::probe::ProbeEndpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        attempts: 1,
        timeout: Duration::from_millis(1),
        probes_per_second: None,
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        limits: Limits::default(),
        route: crate::route::Options::default(),
        collection: crate::exchange::Collection::default(),
    }
}

#[derive(Default)]
struct TimeoutExecutor {
    batches: Vec<(u32, Vec<Option<u16>>)>,
    invalid_sent_sequence: Option<u64>,
    invalid_udp_payload: bool,
}

impl Executor<Batch<Probe>> for TimeoutExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        self.batches.push((
            batch.probes[0].attempt,
            batch
                .probes
                .iter()
                .map(|probe| probe.endpoint.port())
                .collect(),
        ));
        let mut sent = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            match probe.address {
                IpAddr::V4(_) => {
                    packet.get_mut::<Ipv4>().expect("IPv4 probe").source =
                        Ipv4Addr::new(10, 0, 0, 1);
                }
                IpAddr::V6(_) => {
                    packet.get_mut::<Ipv6>().expect("IPv6 probe").source =
                        "fd00::1".parse().unwrap();
                }
            }
            if self.invalid_sent_sequence == Some(probe.sequence) {
                packet.get_mut::<Tcp>().unwrap().sequence ^= 1;
            }
            if self.invalid_udp_payload {
                packet
                    .get_mut::<packetcraftr_core::layer::Raw>()
                    .unwrap()
                    .bytes = bytes::Bytes::from_static(b"changed");
            }
            let receipt = crate::test_support::sent_packet(packet);
            bytes += u64::try_from(receipt.bytes_sent()).unwrap();
            sent.push(receipt);
        }
        Ok(Evidence {
            permit: batch.permit,
            sent,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes,
                elapsed: Duration::from_millis(1),
                capture: packetcraftr_netio::capture::Stats::default(),
            },
        })
    }
}

#[test]
fn udp_payload_reject() {
    use packetcraftr_core::error::Classified as _;
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.endpoints = vec![crate::probe::ProbeEndpoint::Udp { port: 80 }];
    request.udp_payload = bytes::Bytes::from_static(b"payload");
    let mut policy = private_policy();
    policy.max_bytes_per_operation = super::IPV4_PROBE_BYTES;
    let mut executor = TimeoutExecutor::default();
    let error = run(
        &request,
        &mut Admission::new(&policy, &crate::target::SystemResolver),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.byte_limit");
    assert!(executor.batches.is_empty());

    let mut executor = TimeoutExecutor {
        invalid_udp_payload: true,
        ..TimeoutExecutor::default()
    };
    let error = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert!(matches!(error, Error::InvalidEvidence { .. }), "{error:?}");

    let mut executor = TimeoutExecutor::default();
    let report = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap();
    assert_eq!(report.stats.bytes, 20 + 8 + 7);
    request.udp_payload = vec![0; super::MAX_UDP_PAYLOAD_BYTES + 1].into();
    assert!(request.validate().is_err());
    request.udp_payload = bytes::Bytes::from_static(b"x");
    request.endpoints = vec![crate::probe::ProbeEndpoint::Tcp { port: 80 }];
    assert!(request.validate().is_err());
}

struct LateResponseExecutor(TimeoutExecutor);

impl Executor<Batch<Probe>> for LateResponseExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.0.execute(batch)?;
        execution
            .unsolicited
            .push(crate::probe::runner::UnsolicitedCapture {
                decoded: decoded(
                    tcp_packet(
                        Ipv4Addr::new(10, 0, 0, 2),
                        Ipv4Addr::new(10, 0, 0, 1),
                        80,
                        50_000,
                        Tcp::SYN | Tcp::ACK,
                    ),
                    Vec::new(),
                ),
                received_at: None,
                response_deadline: std::time::Instant::now(),
                correlation_expired: true,
            });
        Ok(execution)
    }
}

fn tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    flags: u16,
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port,
            destination_port,
            flags,
            acknowledgment: if flags & Tcp::ACK != 0 { 1 } else { 0 },
            ..Tcp::default()
        });
    packet
}

fn decoded(packet: Packet, diagnostics: Vec<Diagnostic>) -> DecodedPacket {
    decoded_packet(
        packet,
        UNIX_EPOCH + Duration::from_secs(2),
        &[0x45],
        diagnostics,
    )
}

#[test]
fn unsolicited_duplicate_requires_a_winner_and_active_correlation() {
    use crate::probe::runner::{Classifier as _, UnsolicitedCapture};

    let local = Ipv4Addr::new(192, 0, 2, 1);
    let remote = Ipv4Addr::new(192, 0, 2, 2);
    let probe = Probe {
        sequence: 0,
        stage: super::Stage::Scan,
        address: remote.into(),
        scope: None,
        endpoint: crate::probe::ProbeEndpoint::Tcp { port: 80 },
        attempt: 1,
        udp_payload: Default::default(),
        udp_profile: None,
    };
    let sent = crate::test_support::sent_packet(tcp_packet(local, remote, 50_000, 80, Tcp::SYN));
    let received_at = sent.timing().freshness_marker().monotonic();
    let registry = packetcraftr_core::protocol::builtin::registry();
    let classifier = super::evidence::ProbeClassifier {
        registry: &registry,
        target: "192.0.2.2".into(),
        winners: Default::default(),
        rtt: Default::default(),
        discovery: Vec::new(),
    };
    for (has_response, correlation_expired, expected) in [
        (false, false, super::Attribution::Late),
        (true, true, super::Attribution::Late),
        (true, false, super::Attribution::Duplicate),
    ] {
        let capture = UnsolicitedCapture {
            decoded: decoded(
                tcp_packet(remote, local, 80, 50_000, Tcp::SYN | Tcp::ACK),
                Vec::new(),
            ),
            received_at: Some(received_at),
            response_deadline: received_at + Duration::from_secs(1),
            correlation_expired,
        };
        let Some(Event::Unattributed(evidence)) =
            classifier.unsolicited(&probe, &sent, &capture, has_response)
        else {
            panic!("the correlated reply must be retained");
        };
        assert_eq!(evidence.sequence, Some(probe.sequence));
        assert_eq!(evidence.attribution, expected);
    }
}

#[test]
fn serial_scan_reject_wide_collection() {
    let address = "192.0.2.1".parse().unwrap();
    let mut frames = tcp_scan_request(Target::Address(address));
    frames.limits.max_evidence_frames = 16;
    frames.limits.max_undecoded = 16;
    let mut bytes = tcp_scan_request(Target::Address(address));
    bytes.limits.max_evidence_bytes = 1 << 20;

    for (request, field) in [(frames, "capture_max_frames"), (bytes, "capture_max_bytes")] {
        let calls = Arc::new(AtomicUsize::new(0));
        let error = run(
            &request,
            &mut AddressListAuthorizer {
                addresses: vec![address],
            },
            &packetcraftr_core::protocol::builtin::registry(),
            &mut RejectingExecutor {
                calls: Arc::clone(&calls),
            },
            &mut NoopClock,
        )
        .expect_err("the collection captures more than the evidence limits retain");

        assert!(
            matches!(&error, Error::InvalidLimit { field: named, .. } if *named == field),
            "{error:?}"
        );
        assert_eq!(
            packetcraftr_core::error::Classified::classification(&error).code,
            "cli.scan_limit"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[derive(Default)]
struct TargetSetAuthorizer {
    calls: Vec<Target>,
}
impl crate::target::ResolveTarget for TargetSetAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        _deadline: &Deadline,
    ) -> Result<crate::target::Authorized, BoundaryError> {
        self.calls.push(target.clone());
        Ok(crate::target::Authorized {
            declared: target.clone(),
            selected: match target {
                Target::Address(address) => {
                    vec![crate::target::SelectedAddress::new(*address)]
                }
                Target::Hostname(_) | Target::ScopedAddress(_) => {
                    vec!["192.0.2.3".parse().unwrap(), "192.0.2.3".parse().unwrap()]
                        .into_iter()
                        .map(crate::target::SelectedAddress::new)
                        .collect()
                }
            },
        })
    }
}

impl crate::policy::Authorizer for TargetSetAuthorizer {
    fn authorize_operation(
        &mut self,
        _operation: crate::policy::Operation<'_>,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

fn icmp_scan_request(target: Target, attempts: u32, timeout: Duration) -> Request {
    Request {
        endpoints: vec![crate::probe::ProbeEndpoint::Icmp],
        attempts,
        timeout,
        ..tcp_scan_request(target)
    }
}

struct EchoReplyExecutor {
    inner: TimeoutExecutor,
    latency: Duration,
    copies: usize,
}

impl Executor<Batch<Probe>> for EchoReplyExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.inner.execute(batch)?;
        let (IpAddr::V4(remote), crate::probe::ProbeEndpoint::Icmp) =
            (batch.probes[0].address, batch.probes[0].endpoint)
        else {
            return Ok(execution);
        };
        let Some(reply) = execution
            .sent
            .first()
            .and_then(|sent| echo_reply(sent.built().packet.get::<Icmpv4>()?.body.clone(), remote))
        else {
            return Ok(execution);
        };
        for _ in 0..self.copies {
            execution.responses.push(crate::exchange::Response {
                request_index: 0,
                response: decoded(reply.clone(), Vec::new()),
                latency: self.latency,
            });
        }
        Ok(execution)
    }
}

struct EveryOtherEchoExecutor {
    inner: TimeoutExecutor,
}

impl Executor<Batch<Probe>> for EveryOtherEchoExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.inner.execute(batch)?;
        if batch.probes[0].sequence % 2 == 1 {
            return Ok(execution);
        }
        let latency = Duration::from_micros(250 + 250 * (batch.probes[0].sequence / 2));
        let (IpAddr::V4(remote), crate::probe::ProbeEndpoint::Icmp) =
            (batch.probes[0].address, batch.probes[0].endpoint)
        else {
            return Ok(execution);
        };
        let Some(reply) = execution
            .sent
            .first()
            .and_then(|sent| echo_reply(sent.built().packet.get::<Icmpv4>()?.body.clone(), remote))
        else {
            return Ok(execution);
        };
        execution.responses.push(crate::exchange::Response {
            request_index: 0,
            response: decoded(reply, Vec::new()),
            latency,
        });
        Ok(execution)
    }
}

fn echo_reply(body: bytes::Bytes, remote: Ipv4Addr) -> Option<Packet> {
    let mut reply = Packet::new();
    reply
        .push(Ipv4 {
            source: remote,
            destination: Ipv4Addr::new(10, 0, 0, 1),
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type: 0,
            body,
            ..Icmpv4::default()
        });
    Some(reply)
}

struct StaleEchoExecutor {
    inner: TimeoutExecutor,
}

impl Executor<Batch<Probe>> for StaleEchoExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.inner.execute(batch)?;
        let (IpAddr::V4(remote), crate::probe::ProbeEndpoint::Icmp) =
            (batch.probes[0].address, batch.probes[0].endpoint)
        else {
            return Ok(execution);
        };
        let Some(mut body) = execution
            .sent
            .first()
            .and_then(|sent| sent.built().packet.get::<Icmpv4>())
            .map(|icmp| icmp.body.to_vec())
        else {
            return Ok(execution);
        };
        body[3] ^= 0xff;
        if let Some(reply) = echo_reply(bytes::Bytes::from(body), remote) {
            execution.responses.push(crate::exchange::Response {
                request_index: 0,
                response: decoded(reply, Vec::new()),
                latency: Duration::from_micros(500),
            });
        }
        Ok(execution)
    }
}

fn scoped_v6_route(
    interface: packetcraftr_netio::interface::Id,
) -> packetcraftr_netio::route::Decision {
    packetcraftr_netio::route::Decision {
        interface,
        source_mac: None,
        selected_source: Some(IpAddr::V6("fe80::9".parse().unwrap())),
        preferred_source: None,
        next_hop: None,
        selection_reason: packetcraftr_netio::route::SelectionReason::OnLink,
        destination_scope: packetcraftr_netio::route::Scope::Link,
        mtu: 1500,
        capability: packetcraftr_netio::link::Capability::Layer3,
        link_type: packetcraftr_core::frame::LinkType::RAW,
    }
}

fn scoped_request(targets: crate::target::Selection, max_in_flight: usize) -> Request {
    Request {
        target_sources: Vec::new(),
        targets,
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        endpoints: vec![crate::probe::ProbeEndpoint::Tcp { port: 443 }],
        discovery: Default::default(),
        attempts: 1,
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        max_in_flight,
        limits: Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    }
}

fn client_scan(request: Request) -> (Result<Aggregate, Error>, crate::test_support::FakeProviders) {
    let (client, providers) = crate::test_support::fake_client();
    let collector = Collector::default();
    let result = client
        .scan(request, collector.clone())
        .and_then(|report| collector.finish(report));
    (result, providers)
}

#[test]
fn scoped_raw_scan_routes_on_the_resolved_interface() {
    let (client, providers) = crate::test_support::fake_client();
    let fixture = packetcraftr_netio::interface::Id {
        name: "fixture0".to_owned(),
        index: 1,
    };
    // The stage routes the target for its neighbor, then for its probe.
    providers.routes.lock().expect("routes").extend([
        scoped_v6_route(fixture.clone()),
        scoped_v6_route(fixture.clone()),
    ]);
    let collector = Collector::default();
    let request = scoped_request(
        crate::target::Selection {
            include: vec![crate::target::Specification::Target(
                "fe80::1%fixture0".parse().expect("scoped target"),
            )],
            exclude: Vec::new(),
        },
        1,
    );
    let report = client
        .scan(request, collector.clone())
        .and_then(|report| collector.finish(report))
        .expect("scoped scan");

    let scope = report.endpoints[0].scope.as_ref().expect("endpoint scope");
    assert_eq!(scope.interface, fixture);
    assert_eq!(scope.zone.as_str(), "fixture0");
    assert!(providers.calls().iter().any(|call| matches!(
        call,
        Call::RouteOn(destination, interface)
            if *destination == IpAddr::V6("fe80::1".parse().unwrap())
                && *interface == fixture
    )));
}

#[test]
fn scoped_raw_scan_rejects_an_explicit_interface_conflict_before_sends() {
    let (client, providers) = crate::test_support::fake_client();
    let collector = Collector::default();
    let mut request = scoped_request(
        crate::target::Selection {
            include: vec![crate::target::Specification::Target(
                "fe80::1%fixture0".parse().expect("scoped target"),
            )],
            exclude: Vec::new(),
        },
        1,
    );
    request.route.interface = Some(crate::route::Interface::Index(
        std::num::NonZeroU32::new(9).expect("nonzero"),
    ));
    let error = client
        .scan(request, collector.clone())
        .and_then(|report| collector.finish(report))
        .expect_err("conflicting interface");
    assert!(
        matches!(
            error,
            Error::InvalidLimit {
                field: "interface",
                ..
            }
        ),
        "expected the interface conflict limit, got {error}"
    );
    assert!(
        !providers.calls().iter().any(|call| matches!(
            call,
            Call::Route(_) | Call::RouteOn(..) | Call::Transmit(_) | Call::Capture
        )),
        "the conflict still reached providers: {:?}",
        providers.calls()
    );
}

#[test]
fn scoped_raw_scan_rejects_a_mismatched_provider_route_before_sends() {
    let (client, providers) = crate::test_support::fake_client();
    providers
        .routes
        .lock()
        .expect("routes")
        .push_back(scoped_v6_route(packetcraftr_netio::interface::Id {
            name: "other0".to_owned(),
            index: 9,
        }));
    let collector = Collector::default();
    let error = client
        .scan(
            scoped_request(
                crate::target::Selection {
                    include: vec![crate::target::Specification::Target(
                        "fe80::1%fixture0".parse().expect("scoped target"),
                    )],
                    exclude: Vec::new(),
                },
                1,
            ),
            collector.clone(),
        )
        .and_then(|report| collector.finish(report))
        .expect_err("route on the wrong interface is rejected");

    assert!(
        error.to_string().contains("interface")
            || format!("{error:?}").contains("InterfaceMismatch"),
        "expected the interface-mismatch source, got {error:?}"
    );
    assert!(
        !providers
            .calls()
            .iter()
            .any(|call| matches!(call, Call::Transmit(_))),
        "a mismatched route still transmitted: {:?}",
        providers.calls()
    );
}

#[test]
fn scoped_window_routes_each_target_on_its_own_interface() {
    use crate::providers::ProviderSet;
    use crate::test_support::ZoneMapResolver;

    let alpha = packetcraftr_netio::interface::Id {
        name: "alpha".to_owned(),
        index: 2,
    };
    let beta = packetcraftr_netio::interface::Id {
        name: "beta".to_owned(),
        index: 3,
    };
    let fake = crate::test_support::FakeProviders::default();
    // The pipelined stage routes each target to admit it before any traffic,
    // then for its neighbor, then for its probe.
    fake.routes.lock().expect("routes").extend([
        scoped_v6_route(alpha.clone()),
        scoped_v6_route(beta.clone()),
        scoped_v6_route(alpha.clone()),
        scoped_v6_route(beta.clone()),
        scoped_v6_route(alpha.clone()),
        scoped_v6_route(beta.clone()),
    ]);
    let providers = ProviderSet::packet(fake.clone(), fake.clone(), fake.clone(), fake.clone())
        .with_resolver(ZoneMapResolver::new(vec![alpha.clone(), beta.clone()]));
    let client = crate::Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        crate::policy::Policy::default(),
        providers,
    );
    let collector = Collector::default();
    let report = client
        .scan(
            scoped_request(
                crate::target::Selection {
                    include: vec![
                        crate::target::Specification::Target(
                            "fe80::1%alpha".parse().expect("scoped target"),
                        ),
                        crate::target::Specification::Target(
                            "fe80::1%beta".parse().expect("scoped target"),
                        ),
                    ],
                    exclude: Vec::new(),
                },
                2,
            ),
            collector.clone(),
        )
        .and_then(|report| collector.finish(report))
        .expect("two scoped targets");

    let mut interfaces: Vec<u32> = report
        .endpoints
        .iter()
        .map(|endpoint| {
            endpoint
                .scope
                .as_ref()
                .expect("endpoint scope")
                .interface
                .index
        })
        .collect();
    interfaces.sort();
    assert_eq!(interfaces, [2, 3], "zones never merge across interfaces");
    assert_eq!(
        report
            .endpoints
            .iter()
            .map(|e| e.address)
            .collect::<Vec<_>>(),
        vec![IpAddr::V6("fe80::1".parse().unwrap()); 2],
    );
    let routed: Vec<_> = fake
        .calls()
        .iter()
        .filter_map(|call| match call {
            Call::RouteOn(_, interface) => Some(interface.index),
            _ => None,
        })
        .collect();
    let mut routed = routed;
    routed.sort();
    assert_eq!(routed, [2, 2, 2, 3, 3, 3]);
}

#[test]
fn raw_duplicate_diagnostics_keep_source_labels_before_execution() {
    let (client, providers) = crate::test_support::fake_client();
    let mut request = tcp_scan_request(Target::Address("192.0.2.1".parse().unwrap()));
    request.timeout = Duration::from_secs(1);
    request
        .targets
        .include
        .push(request.targets.include[0].clone());
    request.target_sources = vec!["argument 1".to_owned(), "inventory.txt:4".to_owned()];
    let observed = std::sync::Arc::new(std::sync::Mutex::new(false));
    let sink_observed = observed.clone();
    let sink_providers = providers.clone();
    client
        .scan(request, move |event| {
            if let Event::Diagnostic(diagnostic) = event {
                assert_eq!(diagnostic.code, "scan.duplicate_declaration");
                assert!(
                    diagnostic
                        .message
                        .contains("target declaration 2 (inventory.txt:4)")
                );
                assert!(
                    !sink_providers
                        .calls()
                        .iter()
                        .any(|call| matches!(call, Call::Transmit(_)))
                );
                *sink_observed.lock().unwrap() = true;
            }
            Ok(())
        })
        .expect("scan");
    assert!(*observed.lock().unwrap());
}

#[test]
fn invalid_declaration_sources_fail_before_any_provider_call() {
    for sources in [
        vec!["".to_owned()],
        vec!["x".repeat(4097)],
        vec!["a".to_owned(), "b".to_owned()],
    ] {
        let (client, providers) = crate::test_support::fake_client();
        let mut request = tcp_scan_request(Target::Address("192.0.2.1".parse().unwrap()));
        request.target_sources = sources;
        let collector = Collector::default();
        assert!(matches!(
            client.scan(request.clone(), collector),
            Err(Error::InvalidLimit {
                field: "target_sources",
                ..
            })
        ));
        let collector = super::connect::Collector::default();
        assert!(matches!(
            client.scan_connect(request, collector),
            Err(Error::InvalidLimit {
                field: "target_sources",
                ..
            })
        ));
        assert!(providers.calls().is_empty());
    }
}

#[test]
fn discovery_composes_one_record_per_family_and_scans_only_responders() {
    use super::discovery::{Mode, Options, Scan, State};
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let v6: IpAddr = "2001:db8::10".parse().unwrap();
    let mut request = tcp_scan_request(Target::Address(v4));
    request.targets = crate::target::Selection {
        include: [v4, v6]
            .map(|address| crate::target::Specification::Target(Target::Address(address)))
            .to_vec(),
        exclude: Vec::new(),
    };
    request.discovery = Options {
        mode: Mode::Before,
        probes: vec![crate::probe::ProbeEndpoint::Icmp],
        ..Options::default()
    };
    // Only IPv4 echoes draw a reply from this fixture.
    let mut executor = EchoReplyExecutor {
        inner: TimeoutExecutor::default(),
        latency: Duration::from_millis(1),
        copies: 1,
    };
    let report = run(
        &request,
        &mut Admission::new(&private_policy(), &crate::target::SystemResolver),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect("discovery before the scan");

    assert_eq!(
        executor.inner.batches,
        [(1, vec![None]), (1, vec![None]), (1, vec![Some(80)])]
    );
    let states = report
        .hosts
        .iter()
        .map(|host| (host.address, host.state, host.scan))
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        [
            (v4, State::Responded, Scan::Scanned),
            (v6, State::NoResponse, Scan::Skipped),
        ]
    );
    assert_eq!(report.hosts[1].probes, [1]);
    assert_eq!(report.endpoints.len(), 1);
    assert_eq!(report.endpoints[0].probes[0].sequence, 2);
    assert_eq!(report.rtt.sent, 3);
}

#[test]
fn neighbor_requests_are_paced_retried_and_counted_like_probes() {
    use super::discovery::{Link, Mode, NeighborOutcome, NextHop, Options, State};
    let on_link = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let routed = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let link = Link {
        address: packetcraftr_core::packet::MacAddress([2, 0, 0, 0, 0, 0x10]),
        cached: false,
    };
    let mut request = tcp_scan_request(Target::Address(on_link));
    request.targets = crate::target::Selection {
        include: [on_link, routed]
            .map(|address| crate::target::Specification::Target(Target::Address(address)))
            .to_vec(),
        exclude: Vec::new(),
    };
    request.endpoints = Vec::new();
    request.attempts = 2;
    request.probes_per_second = Some(10);
    request.discovery = Options {
        mode: Mode::Only,
        neighbor: true,
        ..Options::default()
    };
    let mut executor = ScriptedNeighbors {
        outcomes: [
            NeighborOutcome::Silent,
            NeighborOutcome::Resolved(link),
            NeighborOutcome::Routed(NextHop {
                address: gateway,
                link: None,
            }),
        ]
        .into(),
        ..ScriptedNeighbors::default()
    };
    let mut clock = crate::test_support::RecordingClock::default();
    let report = engine::run(
        &request,
        &mut Admission::new(&private_policy(), &crate::target::SystemResolver),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut clock,
        &mut Deadline::new(request.limits.max_duration),
        |_, _| Ok(()),
    )
    .expect("neighbor discovery");

    // A silent neighbor is asked again; a routed target's gateway never is.
    assert_eq!(executor.calls, [on_link, on_link, routed]);
    // One interval follows each request; nothing was sent for the last.
    assert_eq!(clock.delays(), [Duration::from_millis(100); 2]);
    assert_eq!(
        (report.stats.packets_attempted, report.stats.bytes),
        (2, 84)
    );
    // The paced intervals count in the statistics like the probe runners'.
    assert_eq!(report.stats.elapsed, Duration::from_millis(200));
    let neighbors = report
        .hosts
        .iter()
        .map(|host| {
            (
                host.state,
                host.neighbor.as_ref().map(|neighbor| neighbor.attempts),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        neighbors,
        [(State::Responded, Some(2)), (State::NoResponse, Some(0))]
    );
}

#[test]
fn icmp_discovery_pairs_with_a_multi_port_scan() {
    use super::discovery::{Mode, Options};
    use crate::probe::ProbeEndpoint;
    let mut request = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
    request.endpoints = vec![
        ProbeEndpoint::Tcp { port: 22 },
        ProbeEndpoint::Tcp { port: 80 },
    ];
    request.discovery = Options {
        mode: Mode::Before,
        probes: vec![ProbeEndpoint::Icmp],
        ..Options::default()
    };
    request
        .validate()
        .expect("ICMP discovery before a two-port scan");

    // The scan's own portless ICMP endpoint still stands alone.
    request.endpoints.insert(0, ProbeEndpoint::Icmp);
    assert!(matches!(request.validate(), Err(Error::InvalidPort { .. })));
}

#[test]
fn discovery_and_scan_endpoints_share_the_port_budget() {
    use super::discovery::{Mode, Options};
    use crate::probe::ProbeEndpoint;
    let mut request = tcp_scan_request(Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
    request.endpoints = vec![ProbeEndpoint::Udp { port: 80 }];
    request.discovery = Options {
        mode: Mode::Before,
        probes: vec![ProbeEndpoint::Tcp { port: 80 }],
        ..Options::default()
    };
    // Each list fits alone; their distinct union does not.
    request.limits.max_ports = 1;
    let error = request
        .validate()
        .expect_err("the combined endpoint set exceeds max_ports");
    assert!(
        matches!(
            error,
            Error::InvalidLimit {
                field: "ports",
                value: 2,
                ..
            }
        ),
        "{error:?}"
    );
    request.limits.max_ports = 2;
    request.validate().expect("two distinct endpoints fit");
}

#[test]
fn link_layer_probes_budget_their_implicit_neighbor_resolution() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mut request = tcp_scan_request(Target::Address(address));
    request.limits.max_probes = 1;
    let error = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut RejectingExecutor {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        &mut NoopClock,
    )
    .expect_err("the probe's implicit neighbor request exceeds max_probes");
    assert!(
        matches!(
            error,
            Error::InvalidLimit {
                field: "probes",
                value: 2,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "cli.scan_limit"
    );

    // A layer-3 route resolves no neighbor, so the probe budget stays exact.
    request.route.link_mode = packetcraftr_netio::link::Mode::Layer3;
    let mut executor = TimeoutExecutor::default();
    let report = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect("layer-3 probes send no implicit neighbor request");
    assert_eq!(report.stats.packets_attempted, 1);
}

#[test]
fn link_layer_probes_reject_evidence_limits_too_small_for_a_neighbor_reply() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mut request = tcp_scan_request(Target::Address(address));
    request.collection.capture.snap_length = 64;
    request.collection.capture.max_bytes = 64;
    request.limits.max_evidence_bytes = 64;
    let calls = Arc::new(AtomicUsize::new(0));
    let error = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut RejectingExecutor {
            calls: Arc::clone(&calls),
        },
        &mut NoopClock,
    )
    .expect_err("an implicit neighbor reply cannot fit in 64 evidence bytes");
    assert!(
        matches!(
            error,
            Error::InvalidLimit {
                field: "max_evidence_bytes",
                value: 64,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // A layer-3 route resolves no neighbor, so the same limits suffice.
    request.route.link_mode = packetcraftr_netio::link::Mode::Layer3;
    let report = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut TimeoutExecutor::default(),
        &mut NoopClock,
    )
    .expect("layer-3 probes capture no neighbor reply");
    assert_eq!(report.stats.packets_attempted, 1);
}

#[test]
fn link_layer_probes_reject_a_snap_length_too_short_for_a_neighbor_reply() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mut request = tcp_scan_request(Target::Address(address));
    // The evidence limits hold a reply; only the requested snap cannot.
    request.collection.capture.snap_length = 64;
    let calls = Arc::new(AtomicUsize::new(0));
    let error = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut RejectingExecutor {
            calls: Arc::clone(&calls),
        },
        &mut NoopClock,
    )
    .expect_err("an implicit neighbor capture is cut at the scan's snap length");
    assert!(
        matches!(
            error,
            Error::InvalidLimit {
                field: "snap_length",
                value: 64,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn multicast_targets_budget_and_bound_no_neighbor_request() {
    // A multicast destination's link address follows from its own.
    let address = IpAddr::V4(Ipv4Addr::new(233, 252, 0, 1));
    let mut request = tcp_scan_request(Target::Address(address));
    request.limits.max_probes = 1;
    request.collection.capture.snap_length = 64;
    let report = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut TimeoutExecutor::default(),
        &mut NoopClock,
    )
    .expect("a multicast probe needs no neighbor request or reply");
    assert_eq!(report.stats.packets_attempted, 1);
}

#[test]
fn explicit_neighbor_discovery_budgets_no_request_for_a_multicast_target() {
    use super::discovery::{Mode, NeighborOutcome, Options};
    use crate::probe::ProbeEndpoint;
    let target = IpAddr::V4(Ipv4Addr::new(233, 252, 0, 1));
    let mut request = tcp_scan_request(Target::Address(target));
    request.discovery = Options {
        mode: Mode::Only,
        neighbor: true,
        probes: vec![ProbeEndpoint::Icmp],
        ..Options::default()
    };
    request.endpoints.clear();
    request.attempts = 2;
    // Two echoes and no neighbor request: the target's link address follows
    // from its own.
    request.limits.max_probes = 2;
    let mut executor = LateEchoNeighbors {
        neighbors: ScriptedNeighbors {
            outcomes: [NeighborOutcome::NotApplicable].into(),
            ..ScriptedNeighbors::default()
        },
        bytes: 64,
        ..LateEchoNeighbors::default()
    };
    let mut clock = crate::test_support::RecordingClock::default();
    let mut deadline = clock.deadline(request.limits.max_duration);
    engine::run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![target],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut clock,
        &mut deadline,
        |_, _| Ok(()),
    )
    .expect("two echoes fit max_probes = 2");
}

#[test]
fn explicit_neighbor_limits_bind_only_a_target_whose_neighbor_resolves() {
    use super::discovery::{Mode, NeighborOutcome, Options};
    use crate::probe::ProbeEndpoint;
    fn run_on(target: IpAddr) -> Result<(), Error> {
        let mut request = tcp_scan_request(Target::Address(target));
        request.discovery = Options {
            mode: Mode::Only,
            neighbor: true,
            probes: vec![ProbeEndpoint::Icmp],
            ..Options::default()
        };
        request.endpoints.clear();
        // Too short for a neighbor reply, though not for an echo.
        request.collection.capture.snap_length = 64;
        let mut executor = LateEchoNeighbors {
            neighbors: ScriptedNeighbors {
                outcomes: [NeighborOutcome::NotApplicable].into(),
                ..ScriptedNeighbors::default()
            },
            bytes: 64,
            ..LateEchoNeighbors::default()
        };
        let mut clock = crate::test_support::RecordingClock::default();
        let mut deadline = clock.deadline(request.limits.max_duration);
        engine::run(
            &request,
            &mut AddressListAuthorizer {
                addresses: vec![target],
            },
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut clock,
            &mut deadline,
            |_, _| Ok(()),
        )
        .map(drop)
    }
    assert!(matches!(
        run_on(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        Err(Error::InvalidDiscovery { .. })
    ));
    // A multicast target's link address follows from its own, so no
    // neighbor capture needs to hold a reply.
    run_on(IpAddr::V4(Ipv4Addr::new(233, 252, 0, 1)))
        .expect("no neighbor capture bounds a multicast target");
}

/// Answers the answered host's discovery echo and gives each scanned probe a
/// late frame its outcome does not carry.
struct SkippedHostExecutor {
    inner: TimeoutExecutor,
    answered: Ipv4Addr,
    bytes: usize,
}

impl Executor<Batch<Probe>> for SkippedHostExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.inner.execute(batch)?;
        let probe = &batch.probes[0];
        match (probe.stage, probe.address) {
            (super::Stage::Discovery, IpAddr::V4(remote)) if remote == self.answered => {
                if let Some(reply) = execution.sent.first().and_then(|sent| {
                    echo_reply(sent.built().packet.get::<Icmpv4>()?.body.clone(), remote)
                }) {
                    execution.responses.push(crate::exchange::Response {
                        request_index: 0,
                        response: decoded(reply, Vec::new()),
                        latency: Duration::from_millis(1),
                    });
                }
            }
            (super::Stage::Scan, IpAddr::V4(remote)) => {
                let mut packet = Packet::new();
                packet.push(Ipv4 {
                    source: remote,
                    destination: Ipv4Addr::new(10, 0, 0, 1),
                    ..Ipv4::default()
                });
                packet.push(Tcp {
                    source_port: 80,
                    destination_port: 50_000,
                    acknowledgment: (probe.sequence as u32).wrapping_add(1),
                    flags: Tcp::SYN | Tcp::ACK,
                    ..Tcp::default()
                });
                execution
                    .unsolicited
                    .push(crate::probe::runner::UnsolicitedCapture {
                        decoded: decoded_packet(
                            packet,
                            UNIX_EPOCH + Duration::from_secs(2),
                            &vec![0x45_u8; self.bytes],
                            Vec::new(),
                        ),
                        received_at: Some(std::time::Instant::now()),
                        response_deadline: std::time::Instant::now() + Duration::from_secs(1),
                        correlation_expired: false,
                    });
            }
            _ => {}
        }
        Ok(execution)
    }
}

#[test]
fn skipped_hosts_release_their_evidence_reservation() {
    use super::discovery::{Mode, Options, State};
    use crate::probe::ProbeEndpoint;
    let answered = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let silent = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let mut request = tcp_scan_request(Target::Address(answered));
    request.targets = crate::target::Selection {
        include: [answered, silent]
            .map(|address| crate::target::Specification::Target(Target::Address(address)))
            .to_vec(),
        exclude: Vec::new(),
    };
    request.discovery = Options {
        mode: Mode::Before,
        probes: vec![ProbeEndpoint::Icmp],
        ..Options::default()
    };
    // Exactly the scanned probe's slot plus one captured frame fits. A
    // layer-3 route resolves no neighbor, so a reply need not fit the snap.
    request.route.link_mode = packetcraftr_netio::link::Mode::Layer3;
    request.collection.capture.snap_length = 64;
    request.collection.capture.max_bytes = 128;
    request.limits.max_evidence_bytes = 128;
    let mut executor = SkippedHostExecutor {
        inner: TimeoutExecutor::default(),
        answered: Ipv4Addr::new(192, 0, 2, 10),
        bytes: 100,
    };
    let report = run(
        &request,
        &mut Admission::new(&private_policy(), &crate::target::SystemResolver),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect("the skipped probe's reservation makes room for late frames");

    assert_eq!(
        report
            .hosts
            .iter()
            .map(|host| (host.address, host.state))
            .collect::<Vec<_>>(),
        [(answered, State::Responded), (silent, State::NoResponse)]
    );
    assert_eq!(report.unattributed.len(), 1);
    assert_eq!(report.unattributed[0].frame.bytes().len(), 100);
    assert!(
        report
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "scan.evidence_limit"),
        "{:?}",
        report.diagnostics
    );
}

/// Scripts neighbor outcomes per call and times out every probe batch,
/// recording the addresses it was asked to probe.
#[derive(Default)]
struct NeighborAwareExecutor {
    neighbors: ScriptedNeighbors,
    inner: TimeoutExecutor,
    probed: Vec<IpAddr>,
}

impl Executor<Batch<Probe>> for NeighborAwareExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        self.probed
            .extend(batch.probes.iter().map(|probe| probe.address));
        self.inner.execute(batch)
    }
}

impl Pipelined for NeighborAwareExecutor {
    fn execute_pipeline(
        &mut self,
        _batches: &[Batch<Probe>],
        _options: PipelineOptions,
        _emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        unreachable!("serial fixtures run one probe in flight")
    }

    fn resolve_neighbor(
        &mut self,
        target: &crate::target::SelectedAddress,
        timeout: Duration,
        deadline: &Deadline,
    ) -> Result<(super::discovery::Neighbor, Stats), BoundaryError> {
        self.neighbors.resolve_neighbor(target, timeout, deadline)
    }
}

#[test]
fn a_silent_neighbor_sends_no_ip_probes_and_is_never_scanned() {
    use super::discovery::{Link, Mode, NeighborOutcome, Options, Scan, State, Unresponsive};
    use crate::probe::ProbeEndpoint;
    let silent = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let answered = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let mut request = tcp_scan_request(Target::Address(answered));
    request.targets = crate::target::Selection {
        include: [silent, answered]
            .map(|address| crate::target::Specification::Target(Target::Address(address)))
            .to_vec(),
        exclude: Vec::new(),
    };
    // `scan` asks to probe unresponsive hosts, but a target whose own link
    // address stayed silent cannot be sent a frame at all.
    request.discovery = Options {
        mode: Mode::Before,
        neighbor: true,
        probes: vec![ProbeEndpoint::Icmp],
        unresponsive: Unresponsive::Scan,
    };
    let mut executor = NeighborAwareExecutor {
        neighbors: ScriptedNeighbors {
            outcomes: [
                NeighborOutcome::Silent,
                NeighborOutcome::Resolved(Link {
                    address: packetcraftr_core::packet::MacAddress([2, 0, 0, 0, 0, 0x10]),
                    cached: false,
                }),
            ]
            .into(),
            ..ScriptedNeighbors::default()
        },
        ..NeighborAwareExecutor::default()
    };
    let report = engine::run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![silent, answered],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &mut Deadline::new(request.limits.max_duration),
        |_, _| Ok(()),
    )
    .expect("a silent neighbor keeps its record without aborting the scan");

    // Only the resolvable host was probed: one discovery echo, then the scan.
    assert_eq!(executor.probed, [answered, answered]);
    assert_eq!(executor.neighbors.calls, [silent, answered]);
    let states = report
        .hosts
        .iter()
        .map(|host| (host.address, host.state, host.scan, host.probes.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        states,
        [
            (silent, State::NoResponse, Scan::Skipped, Vec::new()),
            (answered, State::Responded, Scan::Scanned, vec![0]),
        ]
    );
}

/// Scripts neighbor outcomes per call and answers each discovery echo in
/// time, then again with a late frame its outcome does not carry.
#[derive(Default)]
struct LateEchoNeighbors {
    neighbors: ScriptedNeighbors,
    inner: TimeoutExecutor,
    bytes: usize,
}

impl Executor<Batch<Probe>> for LateEchoNeighbors {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.inner.execute(batch)?;
        let IpAddr::V4(remote) = batch.probes[0].address else {
            return Ok(execution);
        };
        let Some(reply) = execution
            .sent
            .first()
            .and_then(|sent| echo_reply(sent.built().packet.get::<Icmpv4>()?.body.clone(), remote))
        else {
            return Ok(execution);
        };
        execution
            .unsolicited
            .push(crate::probe::runner::UnsolicitedCapture {
                decoded: decoded_packet(
                    reply.clone(),
                    UNIX_EPOCH + Duration::from_secs(2),
                    &vec![0x45_u8; self.bytes],
                    Vec::new(),
                ),
                received_at: Some(std::time::Instant::now()),
                response_deadline: std::time::Instant::now() + Duration::from_secs(1),
                correlation_expired: false,
            });
        execution.responses.push(crate::exchange::Response {
            request_index: 0,
            response: decoded(reply, Vec::new()),
            latency: Duration::from_millis(1),
        });
        Ok(execution)
    }
}

impl Pipelined for LateEchoNeighbors {
    fn execute_pipeline(
        &mut self,
        _batches: &[Batch<Probe>],
        _options: PipelineOptions,
        _emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        unreachable!("serial fixtures run one probe in flight")
    }

    fn resolve_neighbor(
        &mut self,
        target: &crate::target::SelectedAddress,
        timeout: Duration,
        deadline: &Deadline,
    ) -> Result<(super::discovery::Neighbor, Stats), BoundaryError> {
        self.neighbors.resolve_neighbor(target, timeout, deadline)
    }
}

#[test]
fn a_silent_neighbors_skipped_probes_release_their_evidence_reservation() {
    use super::discovery::{Link, Mode, NeighborOutcome, Options, State};
    use crate::probe::ProbeEndpoint;
    let silent = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let answered = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let mut request = tcp_scan_request(Target::Address(answered));
    request.targets = crate::target::Selection {
        include: [silent, answered]
            .map(|address| crate::target::Specification::Target(Target::Address(address)))
            .to_vec(),
        exclude: Vec::new(),
    };
    request.discovery = Options {
        mode: Mode::Only,
        neighbor: true,
        probes: vec![ProbeEndpoint::Icmp],
        ..Options::default()
    };
    request.endpoints.clear();
    // Exactly the answered echo's slot plus one captured frame fits, and
    // the snap length holds a neighbor reply.
    request.collection.capture.snap_length = 128;
    request.collection.capture.max_bytes = 256;
    request.limits.max_evidence_bytes = 256;
    let mut executor = LateEchoNeighbors {
        neighbors: ScriptedNeighbors {
            outcomes: [
                NeighborOutcome::Silent,
                NeighborOutcome::Resolved(Link {
                    address: packetcraftr_core::packet::MacAddress([2, 0, 0, 0, 0, 0x10]),
                    cached: false,
                }),
            ]
            .into(),
            ..ScriptedNeighbors::default()
        },
        bytes: 128,
        ..LateEchoNeighbors::default()
    };
    let mut diagnostics = Vec::new();
    let report = engine::run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![silent, answered],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &mut Deadline::new(request.limits.max_duration),
        |event, _| {
            if let Event::Diagnostic(diagnostic) = event {
                diagnostics.push(diagnostic.code);
            }
            Ok(())
        },
    )
    .expect("a silent neighbor keeps its record without aborting the scan");

    assert!(
        diagnostics.is_empty(),
        "the late echo fits once the skipped probe holds no reservation: {diagnostics:?}"
    );

    assert_eq!(
        report
            .hosts
            .iter()
            .map(|host| (host.address, host.state))
            .collect::<Vec<_>>(),
        [(silent, State::NoResponse), (answered, State::Responded)]
    );
}

/// Answers every neighbor request after marking `work` clock time spent, so
/// the run can observe work that the plan never predicted.
struct SlowNeighbors {
    clock: crate::test_support::RecordingClock,
    work: Duration,
}

impl Executor<Batch<Probe>> for SlowNeighbors {
    fn execute(&mut self, _batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        unreachable!("neighbor-only discovery sends no probe")
    }
}

impl Pipelined for SlowNeighbors {
    fn execute_pipeline(
        &mut self,
        _batches: &[Batch<Probe>],
        _options: PipelineOptions,
        _emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        unreachable!("neighbor-only discovery sends no probe")
    }

    fn resolve_neighbor(
        &mut self,
        _target: &crate::target::SelectedAddress,
        _timeout: Duration,
        _deadline: &Deadline,
    ) -> Result<(super::discovery::Neighbor, Stats), BoundaryError> {
        self.clock.advance(self.work);
        let neighbor = super::discovery::Neighbor {
            outcome: super::discovery::NeighborOutcome::Resolved(super::discovery::Link {
                address: packetcraftr_core::packet::MacAddress([2, 0, 0, 0, 0, 0x10]),
                cached: false,
            }),
            interface: fixture_interface(),
            attempts: 1,
            observed_at: Some(UNIX_EPOCH),
        };
        let stats = Stats {
            packets_attempted: 1,
            packets_completed: 1,
            bytes: 42,
            ..Stats::default()
        };
        Ok((neighbor, stats))
    }
}

#[test]
fn a_neighbor_pace_that_would_overshoot_the_deadline_is_refused() {
    use super::discovery::{Mode, Options};
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mut request = tcp_scan_request(Target::Address(target));
    request.endpoints = Vec::new();
    request.probes_per_second = Some(1);
    request.limits.max_duration = Duration::from_millis(2_100);
    request.discovery = Options {
        mode: Mode::Only,
        neighbor: true,
        ..Options::default()
    };
    let mut clock = crate::test_support::RecordingClock::default();
    let mut deadline = clock.deadline(request.limits.max_duration);
    // The resolution's own route and capture work consumes most of the
    // budget, so the trailing one-second pace cannot fit anymore.
    let mut executor = SlowNeighbors {
        clock: clock.clone(),
        work: Duration::from_millis(1_500),
    };
    let error = engine::run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![target],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut clock,
        &mut deadline,
        |_, _| Ok(()),
    )
    .expect_err("the trailing pace is reserved before it is slept");

    assert!(
        matches!(error, Error::DurationLimit { .. }),
        "expected the pace's reservation to hit the duration limit, got {error:?}"
    );
}

/// Answers every probe with silence after its next hop's resolution sent
/// one request.
#[derive(Default)]
struct FreshNextHops(TimeoutExecutor);

impl Executor<Batch<Probe>> for FreshNextHops {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        self.0.execute(batch)
    }
}

impl Pipelined for FreshNextHops {
    fn execute_pipeline(
        &mut self,
        _batches: &[Batch<Probe>],
        _options: PipelineOptions,
        _emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        unreachable!("serial fixtures run one probe in flight")
    }

    fn resolve_neighbor(
        &mut self,
        _target: &crate::target::SelectedAddress,
        _timeout: Duration,
        _deadline: &Deadline,
    ) -> Result<(super::discovery::Neighbor, Stats), BoundaryError> {
        unreachable!("the request selects no neighbor discovery")
    }

    fn resolve_next_hop(
        &mut self,
        _target: &crate::target::SelectedAddress,
        _deadline: &Deadline,
    ) -> Result<super::executor::NextHopResolution, BoundaryError> {
        Ok(super::executor::NextHopResolution {
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: 42,
                ..Stats::default()
            },
            silence: None,
        })
    }
}

#[test]
fn an_implicit_neighbor_request_paces_like_a_probe() {
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mut request = tcp_scan_request(Target::Address(target));
    request.probes_per_second = Some(10);
    let mut clock = crate::test_support::RecordingClock::default();
    let mut deadline = clock.deadline(request.limits.max_duration);
    let report = engine::run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![target],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut FreshNextHops::default(),
        &mut clock,
        &mut deadline,
        |_, _| Ok(()),
    )
    .expect("the scan fits its budget");

    assert_eq!(
        clock.delays(),
        [Duration::from_millis(100)],
        "the request is spaced from the stage's probe"
    );
    assert_eq!(report.stats.packets_attempted, 2);
}

#[test]
fn explicit_neighbor_discovery_covers_the_implicit_resolution_budget() {
    use super::discovery::{Link, Mode, NeighborOutcome, Options};
    use crate::probe::ProbeEndpoint;
    let target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mut request = tcp_scan_request(Target::Address(target));
    request.discovery = Options {
        mode: Mode::Only,
        neighbor: true,
        probes: vec![ProbeEndpoint::Icmp],
        ..Options::default()
    };
    request.endpoints.clear();
    // One neighbor request and one echo: the echo's stage finds the
    // discovered answer instead of asking again.
    request.limits.max_probes = 2;
    let mut executor = LateEchoNeighbors {
        neighbors: ScriptedNeighbors {
            outcomes: [NeighborOutcome::Resolved(Link {
                address: packetcraftr_core::packet::MacAddress([2, 0, 0, 0, 0, 0x10]),
                cached: false,
            })]
            .into(),
            ..ScriptedNeighbors::default()
        },
        bytes: 64,
        ..LateEchoNeighbors::default()
    };
    let mut clock = crate::test_support::RecordingClock::default();
    let mut deadline = clock.deadline(request.limits.max_duration);
    let report = engine::run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![target],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut clock,
        &mut deadline,
        |_, _| Ok(()),
    )
    .expect("two frames fit max_probes = 2");
    assert_eq!(report.stats.packets_attempted, 2);
}
