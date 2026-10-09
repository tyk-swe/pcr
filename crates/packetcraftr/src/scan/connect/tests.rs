// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_netio::tcp::{self, Provider};

use super::super::{Classification, Error, Limits, Request};
use super::{Aggregate, Collector, Outcome, ProbeEvidence};
use crate::clock::Clock;
use crate::test_support::FakeProviders;
use crate::{Client, ProviderSet};

type Fakes<T> =
    ProviderSet<FakeProviders, FakeProviders, FakeProviders, FakeProviders, T, FakeProviders>;

fn client<T: Provider<Stream: 'static> + Send + Sync + 'static>(tcp: T) -> Client<Fakes<T>> {
    let fake = FakeProviders::default();
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        crate::policy::Policy::default(),
        ProviderSet {
            route: fake.clone(),
            interface: fake.clone(),
            capture: fake.clone(),
            transmit: fake.clone(),
            tcp,
            resolver: fake,
        },
    )
}

fn collect<T: Provider<Stream: 'static> + Send + Sync + 'static>(
    client: &Client<Fakes<T>>,
    request: Request,
) -> Result<Aggregate, Error> {
    let collector = Collector::default();
    let report = client.scan_connect(request, collector.clone())?;
    collector.finish(report)
}

#[derive(Clone, Copy)]
enum Fault {
    PeerQuery(io::ErrorKind),
    LocalQuery(io::ErrorKind),
    OtherPeer,
}

struct Socket {
    peer: SocketAddr,
    closed: Arc<AtomicUsize>,
    fault: Option<Fault>,
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}
impl Read for Socket {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("connect scan must not read application bytes")
    }
}
impl Write for Socket {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        panic!("connect scan must not write application bytes")
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl tcp::Stream for Socket {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self.fault {
            Some(Fault::PeerQuery(kind)) => Err(kind.into()),
            Some(Fault::OtherPeer) => Ok("192.0.2.99:1".parse().unwrap()),
            _ => Ok(self.peer),
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self.fault {
            Some(Fault::LocalQuery(kind)) => Err(kind.into()),
            _ => Ok("127.0.0.1:40000".parse().unwrap()),
        }
    }
    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}
struct Concurrent {
    active: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
    closed: Arc<AtomicUsize>,
}
impl Provider for Concurrent {
    type Stream = Socket;
    fn connect(&self, endpoint: SocketAddr, _deadline: &Deadline) -> Result<Socket, tcp::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(20));
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(Socket {
            peer: endpoint,
            closed: Arc::clone(&self.closed),
            fault: None,
        })
    }
}

struct Verdicts {
    closed: Arc<AtomicUsize>,
}
impl Provider for Verdicts {
    type Stream = Socket;
    fn connect(&self, endpoint: SocketAddr, _deadline: &Deadline) -> Result<Socket, tcp::Error> {
        match endpoint.port() % 3 {
            0 => Ok(Socket {
                peer: endpoint,
                closed: Arc::clone(&self.closed),
                fault: None,
            }),
            1 => Err(io::Error::new(io::ErrorKind::ConnectionRefused, "scripted refusal").into()),
            _ => Err(io::Error::new(io::ErrorKind::TimedOut, "scripted silence").into()),
        }
    }
}

struct Faulty {
    port: u16,
    fault: Fault,
    closed: Arc<AtomicUsize>,
}
impl Provider for Faulty {
    type Stream = Socket;
    fn connect(&self, endpoint: SocketAddr, _deadline: &Deadline) -> Result<Socket, tcp::Error> {
        Ok(Socket {
            peer: endpoint,
            closed: Arc::clone(&self.closed),
            fault: (endpoint.port() == self.port).then_some(self.fault),
        })
    }
}

fn scan_with_fault(fault: Fault) -> (Result<Aggregate, Error>, usize) {
    let request = Request {
        target_sources: Vec::new(),
        targets: crate::target::Target::Address("127.0.0.1".parse().unwrap()).into(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: crate::target::Family::Any,
        endpoints: [80, 81, 82]
            .map(|port| crate::probe::ProbeEndpoint::Tcp { port })
            .to_vec(),
        discovery: Default::default(),
        attempts: 1,
        adaptive: None,
        timeout: Duration::from_secs(5),
        probes_per_second: None,
        max_in_flight: 1,
        limits: Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    };
    let closed = Arc::new(AtomicUsize::new(0));
    let client = client(Faulty {
        port: 81,
        fault,
        closed: Arc::clone(&closed),
    });
    let result = collect(&client, request);
    (result, closed.load(Ordering::SeqCst))
}

fn assert_open_without_local_address(fault: Fault) {
    let (result, closed) = scan_with_fault(fault);
    let report = result.expect("a reset after the handshake must not abort the scan");
    assert_eq!(closed, 3);
    assert_eq!(report.report.stats.connections_succeeded, 3);
    let probes: Vec<_> = report
        .endpoints
        .iter()
        .map(|endpoint| {
            assert_eq!(endpoint.classification, Classification::Open);
            let [probe] = endpoint.probes.as_slice() else {
                panic!("one probe per endpoint");
            };
            (
                probe.sequence,
                probe.connect_succeeded,
                probe.outcome,
                probe.local.is_some(),
            )
        })
        .collect();
    assert_eq!(
        probes,
        [
            (0, Some(true), Outcome::Connected, true),
            (1, Some(true), Outcome::Connected, false),
            (2, Some(true), Outcome::Connected, true),
        ]
    );
}

#[test]
fn connect_scan_keeps_probe_past_peer_reset() {
    assert_open_without_local_address(Fault::PeerQuery(io::ErrorKind::NotConnected));
}

#[test]
fn connect_scan_probe_through_peer_reset() {
    assert_open_without_local_address(Fault::LocalQuery(io::ErrorKind::NotConnected));
}

#[derive(Clone)]
struct Recorded {
    endpoints: Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    closed: Arc<AtomicUsize>,
}
impl Provider for Recorded {
    type Stream = Socket;
    fn connect(&self, endpoint: SocketAddr, _deadline: &Deadline) -> Result<Socket, tcp::Error> {
        self.endpoints.lock().expect("recorded").push(endpoint);
        Ok(Socket {
            peer: endpoint,
            closed: Arc::clone(&self.closed),
            fault: None,
        })
    }
}

#[test]
fn connect_reaches_the_provider_with_the_scoped_socket() {
    let recorded = Recorded {
        endpoints: Arc::new(std::sync::Mutex::new(Vec::new())),
        closed: Arc::new(AtomicUsize::new(0)),
    };
    let client = client(recorded.clone());
    let request = Request {
        target_sources: Vec::new(),
        targets: crate::target::Selection {
            include: vec![crate::target::Specification::Target(
                "fe80::1%fixture0".parse().expect("scoped target"),
            )],
            exclude: Vec::new(),
        },
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: crate::target::Family::Any,
        endpoints: vec![crate::probe::ProbeEndpoint::Tcp { port: 443 }],
        discovery: Default::default(),
        attempts: 1,
        adaptive: None,
        timeout: Duration::from_secs(5),
        probes_per_second: None,
        max_in_flight: 1,
        limits: Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    };
    let report = collect(&client, request).expect("scoped connect");
    let endpoints = recorded.endpoints.lock().expect("recorded");
    let [endpoint] = endpoints.as_slice() else {
        panic!("exactly one scoped connect");
    };
    let std::net::SocketAddr::V6(socket) = endpoint else {
        panic!("a scoped target must connect on SocketAddrV6");
    };
    assert_eq!(
        socket.ip(),
        &std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
    );
    assert_eq!(
        socket.scope_id(),
        1,
        "the resolved interface index is the scope"
    );
    assert_eq!(
        report.endpoints[0].scope.as_ref().unwrap().interface.index,
        1
    );
}

fn adaptive_request(endpoints: Vec<u16>, attempts: u32, host_timeout: Duration) -> Request {
    Request {
        target_sources: Vec::new(),
        targets: crate::target::Target::Address("127.0.0.1".parse().unwrap()).into(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: crate::target::Family::Any,
        endpoints: endpoints
            .into_iter()
            .map(|port| crate::probe::ProbeEndpoint::Tcp { port })
            .collect(),
        discovery: Default::default(),
        attempts,
        adaptive: Some(crate::scan::Adaptive {
            min_timeout: Duration::from_millis(1),
            max_timeout: Duration::from_millis(500),
            min_window: 1,
            initial_window: 2,
            host_timeout,
            retry_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(4),
        }),
        timeout: Duration::from_millis(200),
        probes_per_second: None,
        max_in_flight: 2,
        limits: Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    }
}

#[test]
fn adaptive_connect_reports_mode_ceilings_and_outcomes() {
    let client = client(Verdicts {
        closed: Arc::new(AtomicUsize::new(0)),
    });
    let request = adaptive_request(vec![80, 81, 82], 1, Duration::from_secs(5));
    let report = collect(&client, request).expect("adaptive connect scan");
    let scheduling = &report.report.scheduling;
    assert_eq!(scheduling.mode, crate::scan::SchedulingMode::Adaptive,);
    assert!(scheduling.adaptive.is_some());
    assert_eq!(scheduling.operation_ceiling, Some(2));
    assert_eq!(
        scheduling.process_ceiling,
        Some(tcp::MAX_PENDING_CONNECTIONS)
    );
    let classifications: Vec<_> = report
        .endpoints
        .iter()
        .map(|endpoint| endpoint.classification)
        .collect();
    assert_eq!(
        classifications,
        [
            Classification::Timeout,
            Classification::Open,
            Classification::Closed
        ]
    );
    assert!(report.report.scheduling.incomplete.is_empty());
}

struct Silent {
    calls: Arc<AtomicUsize>,
}
impl Provider for Silent {
    type Stream = Socket;
    fn connect(&self, _: SocketAddr, _: &Deadline) -> Result<Socket, tcp::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::new(io::ErrorKind::TimedOut, "scripted silence").into())
    }
}

#[test]
fn adaptive_connect_retries_only_retryable_outcomes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let client = client(Silent {
        calls: Arc::clone(&calls),
    });
    let request = adaptive_request(vec![80], 3, Duration::from_secs(5));
    let report = collect(&client, request).expect("adaptive retries a timed-out port");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(report.report.scheduling.retries_started, 2);
    let [endpoint] = report.endpoints.as_slice() else {
        panic!("one endpoint");
    };
    assert_eq!(endpoint.probes.len(), 3);
}

struct Slow {
    closed: Arc<AtomicUsize>,
}
impl Provider for Slow {
    type Stream = Socket;
    fn connect(&self, _: SocketAddr, _: &Deadline) -> Result<Socket, tcp::Error> {
        std::thread::sleep(Duration::from_millis(30));
        Err(io::Error::new(io::ErrorKind::TimedOut, "scripted silence").into())
    }
}

#[test]
fn adaptive_connect_marks_a_deadline_spent_host_incomplete() {
    let client = client(Slow {
        closed: Arc::new(AtomicUsize::new(0)),
    });
    let request = adaptive_request(vec![80, 81], 3, Duration::from_millis(5));
    let report = collect(&client, request).expect("adaptive host deadline");
    assert_eq!(
        report.report.hosts[0].scan,
        crate::scan::discovery::Scan::Incomplete,
    );
    assert_eq!(report.report.scheduling.incomplete.len(), 1);
}

#[test]
fn adaptive_connect_preparation_charge_fails_before_any_socket() {
    let calls = Arc::new(AtomicUsize::new(0));
    let client = client(Silent {
        calls: Arc::clone(&calls),
    });
    let mut request = adaptive_request(vec![80], 32, Duration::from_secs(5));
    request.limits.max_prepared_bytes = 16;
    let error = collect(&client, request).expect_err("a tiny preparation cap fails closed");
    assert!(
        matches!(error, Error::PipelineExecution { .. }),
        "expected a preparation limit failure, got {error:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no socket was started");
}

#[test]
fn a_never_attempted_connect_probe_settles_as_omitted_not_silent() {
    let probe = ProbeEvidence {
        sequence: 7,
        stage: crate::scan::Stage::Scan,
        endpoint: "192.0.2.1:80".parse().unwrap(),
        scope: None,
        attempt: 2,
        attempted: false,
        connect_succeeded: None,
        outcome: Outcome::DeadlineExpired,
        scheduled_at: std::time::SystemTime::now(),
        finished_at: None,
        elapsed: Duration::ZERO,
        local: None,
        error: None,
    };
    assert!(matches!(
        super::engine::connect_outcome(&probe),
        crate::scan::adaptive::Outcome::Omitted
    ));
    let attempted = ProbeEvidence {
        attempted: true,
        ..probe.clone()
    };
    assert!(matches!(
        super::engine::connect_outcome(&attempted),
        crate::scan::adaptive::Outcome::Silent
    ));
}

#[test]
fn connect_replies_carry_no_control_responder_and_unreachable_is_not_one() {
    let probe = ProbeEvidence {
        sequence: 7,
        stage: crate::scan::Stage::Scan,
        endpoint: "192.0.2.1:80".parse().unwrap(),
        scope: None,
        attempt: 1,
        attempted: true,
        connect_succeeded: Some(false),
        outcome: Outcome::Refused,
        scheduled_at: std::time::SystemTime::now(),
        finished_at: None,
        elapsed: Duration::from_millis(5),
        local: None,
        error: None,
    };
    let crate::scan::adaptive::Outcome::Reply { control, .. } =
        super::engine::connect_outcome(&probe)
    else {
        panic!("a refused socket is still a definitive reply");
    };
    assert!(!control, "a refusal proves no control responder");
    let unreachable = ProbeEvidence {
        outcome: Outcome::Unreachable,
        ..probe.clone()
    };
    assert!(matches!(
        super::engine::connect_outcome(&unreachable),
        crate::scan::adaptive::Outcome::Aborted
    ));
    let connected = ProbeEvidence {
        connect_succeeded: Some(true),
        outcome: Outcome::Connected,
        ..probe.clone()
    };
    let crate::scan::adaptive::Outcome::Reply { control, .. } =
        super::engine::connect_outcome(&connected)
    else {
        panic!("a connected socket is a definitive reply");
    };
    assert!(!control);
}

/// A test clock whose authorization time is fully scripted: `sleep` yields
/// to any async fake worker without consuming virtual time, while the
/// authorizer's `advance` supplies the delay a real one would spend. The
/// operation deadline stays real to bound the test itself.
#[derive(Clone, Default)]
struct AuthorizationClock(crate::test_support::RecordingClock);

impl crate::clock::Clock for AuthorizationClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        self.0.now()
    }

    fn sleep(&self, _: Duration, _: &Deadline) -> Result<(), Self::Error> {
        std::thread::yield_now();
        Ok(())
    }
}

struct SlowAuthorize {
    selected: SocketAddr,
    delay: Duration,
    clock: Option<crate::test_support::RecordingClock>,
}

impl crate::target::ResolveTarget for SlowAuthorize {
    fn resolve_and_authorize(
        &mut self,
        target: &crate::target::Target,
        _: &Deadline,
    ) -> Result<crate::target::Authorized, BoundaryError> {
        Ok(crate::target::Authorized {
            declared: target.clone(),
            selected: vec![crate::target::SelectedAddress::new(self.selected.ip())],
        })
    }
}

impl crate::policy::Authorizer for SlowAuthorize {
    fn authorize_operation(
        &mut self,
        operation: crate::policy::Operation<'_>,
    ) -> Result<(), BoundaryError> {
        if let crate::policy::Operation::Socket(_) = operation {
            if let Some(clock) = &self.clock {
                clock.advance(self.delay);
            } else {
                std::thread::sleep(self.delay);
            }
        }
        Ok(())
    }
}

#[test]
fn the_host_deadline_runs_from_selection_so_late_authorization_omits_work() {
    let provider = Arc::new(RefusedAll {
        calls: AtomicUsize::new(0),
    });
    let mut request = adaptive_request(vec![80, 81], 1, Duration::from_secs(30));
    request.max_in_flight = 1;
    request.timeout = Duration::from_secs(30);
    // The declared bound must cover the planned worst case (two exchanges
    // plus backoff spacing); the real operation deadline below stays 60s.
    request.limits.max_duration = Duration::from_secs(65);
    {
        let adaptive = request.adaptive.as_mut().unwrap();
        adaptive.min_timeout = Duration::from_secs(30);
        adaptive.max_timeout = Duration::from_secs(30);
        adaptive.min_window = 1;
        adaptive.initial_window = 1;
    }
    let clock = AuthorizationClock::default();
    let mut authorizer = SlowAuthorize {
        selected: "127.0.0.1:80".parse().unwrap(),
        // Script admission at 20s and 40s around the anchored 30s deadline,
        // without relying on wall-clock authorization sleeps.
        delay: Duration::from_secs(20),
        clock: Some(clock.0.clone()),
    };
    let mut deadline = Deadline::new(Duration::from_secs(60));
    let report = super::engine::run(
        &request,
        &mut authorizer,
        &provider,
        &clock,
        &mut deadline,
        clock.now(),
        |_, _| Ok(()),
    )
    .expect("the scan completes inside its operation deadline");
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        1,
        "authorization past the anchored deadline omits the second port"
    );
    assert_eq!(report.scheduling.incomplete.len(), 1);
}

struct RefusedAll {
    calls: AtomicUsize,
}
impl Provider for RefusedAll {
    type Stream = Socket;
    fn connect(&self, _: SocketAddr, _: &Deadline) -> Result<Socket, tcp::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::new(io::ErrorKind::ConnectionRefused, "scripted refusal").into())
    }
}

#[test]
fn the_descriptor_queue_caps_pending_even_when_leases_free_early() {
    for adaptive in [false, true] {
        let provider = Arc::new(RefusedAll {
            calls: AtomicUsize::new(0),
        });
        let mut request = adaptive_request((80..144).collect(), 1, Duration::from_secs(5));
        request.max_in_flight = 64;
        request.limits.max_duration = Duration::from_secs(60);
        if adaptive {
            let adaptive = request.adaptive.as_mut().unwrap();
            adaptive.min_timeout = Duration::from_millis(200);
            adaptive.max_timeout = Duration::from_millis(200);
            adaptive.initial_window = 64;
        } else {
            request.adaptive = None;
        }
        let mut authorizer = SlowAuthorize {
            selected: "127.0.0.1:80".parse().unwrap(),
            delay: Duration::from_millis(2),
            clock: None,
        };
        let clock = crate::test_support::NoopClock;
        let mut deadline = Deadline::new(Duration::from_secs(60));
        let calls_at_first = Arc::new(std::sync::Mutex::new(None::<usize>));
        let provider_calls = Arc::clone(&provider);
        let first = Arc::clone(&calls_at_first);
        let report = super::engine::run(
            &request,
            &mut authorizer,
            &provider,
            &clock,
            &mut deadline,
            clock.now(),
            move |_, _| {
                let mut first = first.lock().unwrap();
                if first.is_none() {
                    *first = Some(provider_calls.calls.load(Ordering::SeqCst));
                }
                Ok(())
            },
        )
        .expect("all refused endpoints still settle");
        assert!(
            calls_at_first.lock().unwrap().unwrap() <= tcp::MAX_PENDING_CONNECTIONS,
            "adaptive={adaptive}: the queue admits no more than the native descriptor ceiling"
        );
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            64,
            "adaptive={adaptive} incomplete={:?} stats={:?}",
            report.scheduling.incomplete,
            report.stats
        );
        if !adaptive {
            assert!(
                report.scheduling.observed_peak_window <= tcp::MAX_PENDING_CONNECTIONS,
                "{}",
                report.scheduling.observed_peak_window
            );
        }
    }
}

#[test]
fn the_connect_charge_uses_the_effective_descriptor_cap() {
    for adaptive in [false, true] {
        let mut request = adaptive_request((80..144).collect(), 1, Duration::from_secs(5));
        request.max_in_flight = 64;
        request.limits.max_duration = Duration::from_secs(60);
        if !adaptive {
            request.adaptive = None;
        }
        let targets = [crate::target::SelectedAddress::new(
            "127.0.0.1".parse().unwrap(),
        )];
        let effective = tcp::MAX_PENDING_CONNECTIONS;
        let mut charge = targets.len() * 64 * std::mem::size_of::<SocketAddr>()
            + targets.len() * 2 * std::mem::size_of::<crate::target::SelectedAddress>()
            + 64 * std::mem::size_of::<u16>()
            + effective * std::mem::size_of::<super::engine::Active<Socket>>();
        if adaptive {
            charge += super::super::adaptive::state_charge(
                targets.len(),
                64,
                effective,
                super::super::adaptive::scoped_bytes(&targets),
                0,
            );
        }
        let mut authorizer = SlowAuthorize {
            selected: "127.0.0.1:80".parse().unwrap(),
            delay: Duration::ZERO,
            clock: None,
        };
        let deadline = Deadline::new(Duration::from_secs(60));
        request.limits.max_prepared_bytes = charge;
        super::engine::planned(
            &request,
            &mut authorizer,
            &deadline,
            std::mem::size_of::<super::engine::Active<Socket>>(),
        )
        .expect("the effective-cap charge fits");
        request.limits.max_prepared_bytes = charge - 1;
        assert!(
            super::engine::planned(
                &request,
                &mut authorizer,
                &deadline,
                std::mem::size_of::<super::engine::Active<Socket>>(),
            )
            .is_err(),
            "adaptive={adaptive}: one byte under the effective charge rejects"
        );
    }
}
