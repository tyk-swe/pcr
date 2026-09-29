// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified as _;
use packetcraftr_netio::tcp::{self, Provider};

use super::super::{Classification, Error, Limits, Request};
use super::{Aggregate, Collector, Outcome};
use crate::probe::Transport;
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
#[test]
fn connect_windows_overlap_with_stable_identity_and_closed_socket_evidence() {
    let request = Request {
        targets: crate::target::Target::Address("127.0.0.1".parse().unwrap()).into(),
        transport: Transport::Tcp,
        tcp_mode: Default::default(),
        shuffle_seed: None,
        tcp_profiles: Default::default(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: crate::target::Family::Any,
        ports: vec![80, 81, 82, 83],
        attempts: 1,
        timeout: Duration::from_secs(1),
        probes_per_second: None,
        max_in_flight: 2,
        limits: Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    };
    let closed = Arc::new(AtomicUsize::new(0));
    let client = client(Concurrent {
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
        closed: Arc::clone(&closed),
    });
    let provider = &client.providers().tcp;
    let report = collect(&client, request.clone()).unwrap();
    assert_eq!(provider.peak.load(Ordering::SeqCst), 2);
    assert_eq!(closed.load(Ordering::SeqCst), 4);
    assert_eq!(report.report.stats.connections_attempted, 4);
    assert_eq!(
        report
            .endpoints
            .iter()
            .flat_map(|endpoint| endpoint.probes.iter().map(|probe| probe.sequence))
            .collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    let mut bounded = request;
    bounded.limits.max_probes = 1;
    assert!(collect(&client, bounded).is_err());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 4);
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

#[test]
fn connect_scan_reports_rtt_statistics_across_verdicts() {
    let request = Request {
        targets: crate::target::Target::Address("127.0.0.1".parse().unwrap()).into(),
        transport: Transport::Tcp,
        tcp_mode: Default::default(),
        shuffle_seed: None,
        tcp_profiles: Default::default(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: crate::target::Family::Any,
        ports: vec![90, 91, 92],
        attempts: 2,
        timeout: Duration::from_secs(5),
        probes_per_second: None,
        max_in_flight: 1,
        limits: Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    };
    let closed = Arc::new(AtomicUsize::new(0));
    let client = client(Verdicts {
        closed: Arc::clone(&closed),
    });
    let report = collect(&client, request).unwrap();

    let stats = &report.report.stats;
    assert_eq!(stats.connections_scheduled, 6);
    assert_eq!(stats.connections_attempted, 6);
    assert_eq!(stats.connections_succeeded, 2);
    assert_eq!(stats.rtt.sent, 6);
    assert_eq!(stats.rtt.received, 4);
    assert_eq!(stats.rtt.lost, 2);
    let (Some(min), Some(avg), Some(max)) = (stats.rtt.min, stats.rtt.avg, stats.rtt.max) else {
        panic!("received probes must produce RTT samples");
    };
    assert!(
        min <= avg && avg <= max,
        "min {min:?} avg {avg:?} max {max:?}"
    );
    let endpoint_verdicts: Vec<_> = report
        .endpoints
        .iter()
        .map(|endpoint| (endpoint.port, endpoint.classification))
        .collect();
    assert_eq!(
        endpoint_verdicts,
        [
            (90, Classification::Open),
            (91, Classification::Closed),
            (92, Classification::Timeout),
        ]
    );
    assert_eq!(closed.load(Ordering::SeqCst), 2);
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
        targets: crate::target::Target::Address("127.0.0.1".parse().unwrap()).into(),
        transport: Transport::Tcp,
        tcp_mode: Default::default(),
        shuffle_seed: None,
        tcp_profiles: Default::default(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: crate::target::Family::Any,
        ports: vec![80, 81, 82],
        attempts: 1,
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
fn connect_scan_keeps_a_connected_probe_whose_peer_reset_before_the_peer_query() {
    assert_open_without_local_address(Fault::PeerQuery(io::ErrorKind::NotConnected));
}

#[test]
fn connect_scan_keeps_a_connected_probe_whose_peer_reset_before_the_local_query() {
    assert_open_without_local_address(Fault::LocalQuery(io::ErrorKind::NotConnected));
}

#[test]
fn connect_scan_fails_on_endpoint_query_errors_other_than_a_reset_connection() {
    for fault in [
        Fault::PeerQuery(io::ErrorKind::PermissionDenied),
        Fault::LocalQuery(io::ErrorKind::PermissionDenied),
    ] {
        let (result, _) = scan_with_fault(fault);
        let error = result.unwrap_err();
        assert!(matches!(error, Error::Execution { sequence: 1, .. }));
        assert_eq!(error.classification().code, "io.tcp_connect_evidence");
    }
}

#[test]
fn connect_scan_fails_when_the_provider_reports_another_peer_endpoint() {
    let (result, _) = scan_with_fault(Fault::OtherPeer);
    assert!(matches!(
        result.unwrap_err(),
        Error::InvalidEvidence { sequence: 1, .. }
    ));
}
