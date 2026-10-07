// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native TCP connect admission is process-wide, so these contracts run in
//! their own test binary rather than beside other connect tests.

mod common;

use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use common::clock::VirtualClock;
use packetcraftr::clock::Clock;
use packetcraftr::policy::Policy;
use packetcraftr::scan::{self, connect};
use packetcraftr::target::{Family, SystemResolver, Target};
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{Classified as _, Kind};
use packetcraftr_netio::resources::tcp_connect_snapshot;
use packetcraftr_netio::tcp::{MAX_PENDING_CONNECTIONS, Provider, Stream};

const WATCHDOG: Duration = Duration::from_secs(10);
static CONNECT_TESTS: Mutex<()> = Mutex::new(());

fn wait_until(description: &str, ready: impl Fn() -> bool) {
    let until = Instant::now() + WATCHDOG;
    while !ready() {
        assert!(Instant::now() < until, "{description}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

struct Socket;

impl Read for Socket {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Stream for Socket {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::from(io::ErrorKind::NotConnected))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::from(io::ErrorKind::NotConnected))
    }
    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct GateState {
    entered: usize,
    released: usize,
}

#[derive(Default)]
struct ConnectGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl ConnectGate {
    fn hold(&self) {
        let mut state = self.state.lock().unwrap();
        let ticket = state.entered;
        state.entered += 1;
        self.changed.notify_all();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, WATCHDOG, |state| state.released <= ticket)
            .unwrap();
        let released = state.released > ticket;
        drop(state);
        assert!(released, "provider cleanup must be released");
    }

    fn wait_for_entries(&self, expected: usize) {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, WATCHDOG, |state| state.entered < expected)
            .unwrap();
        let entered = state.entered;
        drop(state);
        assert_eq!(entered, expected, "every worker enters its provider");
    }

    fn release(&self, count: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.released = state.released.max(count);
        self.changed.notify_all();
    }
}

struct Cleanup(Arc<ConnectGate>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.0.release(usize::MAX);
    }
}

struct Held(Arc<ConnectGate>);

impl Provider for Held {
    type Stream = Socket;
    fn connect(
        &self,
        _: SocketAddr,
        _: &Deadline,
    ) -> Result<Socket, packetcraftr_netio::tcp::Error> {
        self.0.hold();
        Err(io::Error::from(io::ErrorKind::TimedOut).into())
    }
}

enum Stage {
    FirstProviders,
    RetainedAdmission,
    SecondProviders,
    Finished,
}

#[derive(Clone)]
struct AdmissionClock {
    clock: VirtualClock,
    gate: Arc<ConnectGate>,
    stage: Arc<Mutex<Stage>>,
    timeout: Duration,
    rejected_before: usize,
}

impl Clock for AdmissionClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        self.clock.now()
    }

    fn sleep(&self, _: Duration, _: &Deadline) -> Result<(), Self::Error> {
        let mut stage = self.stage.lock().unwrap();
        match *stage {
            Stage::FirstProviders => {
                self.gate.wait_for_entries(MAX_PENDING_CONNECTIONS);
                self.clock.advance(self.timeout);
                *stage = Stage::RetainedAdmission;
            }
            Stage::RetainedAdmission => {
                let snapshot = tcp_connect_snapshot();
                assert_eq!(snapshot.active, MAX_PENDING_CONNECTIONS);
                assert_eq!(snapshot.cleanup_retaining_capacity, MAX_PENDING_CONNECTIONS);
                assert!(snapshot.rejected_admissions > self.rejected_before);
                self.gate.release(MAX_PENDING_CONNECTIONS);
                wait_until("first-wave admission returns", || {
                    tcp_connect_snapshot().active == 0
                });
                *stage = Stage::SecondProviders;
            }
            Stage::SecondProviders => {
                self.gate.wait_for_entries(2 * MAX_PENDING_CONNECTIONS);
                self.clock.advance(self.timeout);
                *stage = Stage::Finished;
            }
            Stage::Finished => panic!("both waves should expire without another wait"),
        }
        Ok(())
    }
}

fn request() -> scan::Request {
    scan::Request {
        target_sources: Vec::new(),
        targets: Target::Address("192.0.2.10".parse().unwrap()).into(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        endpoints: (1..=32)
            .map(|port| packetcraftr::probe::ProbeEndpoint::Tcp { port })
            .collect(),
        attempts: 1,
        timeout: Duration::from_millis(50),
        probes_per_second: None,
        max_in_flight: MAX_PENDING_CONNECTIONS,
        limits: scan::Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    }
}

#[test]
fn timed_out_not_fail_scan() {
    let _serial = CONNECT_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    wait_until("previous native cleanup completes", || {
        tcp_connect_snapshot().active == 0
    });
    let gate = Arc::new(ConnectGate::default());
    let _cleanup = Cleanup(Arc::clone(&gate));
    // Native dispatch gets a bounded watchdog, but the client clock expires
    // attempts immediately after every provider enters, without a real sleep.
    let request = scan::Request {
        timeout: WATCHDOG,
        ..request()
    };
    let clock = AdmissionClock {
        clock: VirtualClock::default(),
        gate: Arc::clone(&gate),
        stage: Arc::new(Mutex::new(Stage::FirstProviders)),
        timeout: request.timeout,
        rejected_before: tcp_connect_snapshot().rejected_admissions,
    };
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(Held(Arc::clone(&gate)), SystemResolver),
    )
    .with_clock(clock.clone());
    let collector = connect::Collector::default();
    let report = client
        .scan_connect(request, collector.clone())
        .expect("capacity held by cancelled attempts is waited for");
    let aggregate = collector.finish(report).unwrap();
    assert!(matches!(*clock.stage.lock().unwrap(), Stage::Finished));
    assert_eq!(aggregate.report.stats.connections_attempted, 32);
    let probes = aggregate
        .endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.probes)
        .collect::<Vec<_>>();
    assert_eq!(probes.len(), 32);
    assert!(probes.iter().all(|probe| probe.connect_succeeded.is_none()));
    assert!(
        probes
            .iter()
            .all(|probe| probe.outcome == connect::Outcome::DeadlineExpired)
    );
    // Exhausted capacity was waited for, and expired attempts are operational
    // failures: neither becomes a port state.
    for endpoint in &aggregate.endpoints {
        let sequences: Vec<_> = endpoint.probes.iter().map(|probe| probe.sequence).collect();
        assert_eq!(endpoint.inference.state, None);
        assert_eq!(endpoint.inference.rule, scan::Rule::OperationalFailure);
        assert_eq!(endpoint.inference.failed, sequences);
    }
    assert_eq!(
        tcp_connect_snapshot().cleanup_retaining_capacity,
        MAX_PENDING_CONNECTIONS
    );
    gate.release(usize::MAX);
    wait_until("second-wave admission returns", || {
        tcp_connect_snapshot().active == 0
    });
}

#[test]
fn route_overrides_reject_before_tcp_connect() {
    struct CountConnects(Arc<AtomicUsize>);

    impl Provider for CountConnects {
        type Stream = Socket;

        fn connect(
            &self,
            _: SocketAddr,
            _: &Deadline,
        ) -> Result<Socket, packetcraftr_netio::tcp::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::from(io::ErrorKind::ConnectionRefused).into())
        }
    }

    let _serial = CONNECT_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    wait_until("previous native cleanup completes", || {
        tcp_connect_snapshot().active == 0
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(CountConnects(Arc::clone(&calls)), SystemResolver),
    );
    let request = scan::Request {
        endpoints: vec![packetcraftr::probe::ProbeEndpoint::Tcp { port: 80 }],
        max_in_flight: 1,
        timeout: WATCHDOG,
        ..request()
    };
    client
        .scan_connect(request.clone(), connect::Collector::default())
        .expect("default routing permits TCP connects");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    for route in [
        packetcraftr::route::Options {
            interface: Some(packetcraftr::route::Interface::Name(
                "nonexistent0".to_owned(),
            )),
            ..Default::default()
        },
        packetcraftr::route::Options {
            preferred_source: Some("192.0.2.1".parse().unwrap()),
            ..Default::default()
        },
        packetcraftr::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer2,
            ..Default::default()
        },
        packetcraftr::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer3,
            ..Default::default()
        },
    ] {
        let result = client.scan_connect(
            scan::Request {
                route,
                ..request.clone()
            },
            connect::Collector::default(),
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no connect for an unsupported route"
        );
        let error = result.expect_err("kernel TCP cannot honor route overrides");
        assert_eq!(error.classification().code, "capability.scan_tcp_route");
        assert_eq!(error.classification().kind, Kind::Capability);
    }
}
