// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Mutex, mpsc};
use std::time::Duration;

use packetcraftr::policy::Policy;
use packetcraftr::probe::Transport;
use packetcraftr::scan::{self, connect};
use packetcraftr::target::{Family, SystemResolver, Target};
use packetcraftr::{Client, ProviderSet, Sink};
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp;

use common::clock::VirtualClock;

struct Blocked(Mutex<mpsc::Receiver<()>>);

impl tcp::Provider for Blocked {
    type Stream = tcp::SystemStream;

    fn connect(&self, _: SocketAddr, _: &Deadline) -> Result<Self::Stream, tcp::Error> {
        let _ = self.0.lock().unwrap().recv_timeout(Duration::from_secs(5));
        Err(io::Error::from(io::ErrorKind::TimedOut).into())
    }
}

#[test]
fn an_attempt_expires_on_the_client_clock_before_the_operation_deadline() {
    let (release, blocked) = mpsc::channel();
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(Blocked(Mutex::new(blocked)), SystemResolver),
    )
    .with_clock(VirtualClock::default());
    let timeout = Duration::from_millis(20);
    let request = scan::Request {
        targets: Target::Address("192.0.2.10".parse().unwrap()).into(),
        transport: Transport::Tcp,
        tcp_mode: Default::default(),
        shuffle_seed: None,
        tcp_profiles: Default::default(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        ports: vec![53],
        attempts: 1,
        timeout,
        probes_per_second: None,
        max_in_flight: 1,
        limits: scan::Limits {
            max_duration: Duration::from_millis(50),
            ..Default::default()
        },
        route: Default::default(),
        collection: Default::default(),
    };
    let collector = connect::Collector::default();
    let report = client.scan_connect(request, collector.clone());
    drop(release);
    let aggregate = collector
        .finish(report.expect("the attempt expires first"))
        .unwrap();
    let probe = &aggregate.endpoints[0].probes[0];
    assert_eq!(probe.outcome, connect::Outcome::DeadlineExpired);
    assert_eq!(probe.elapsed, timeout);
    assert_eq!(probe.connect_succeeded, None);
    assert_eq!(aggregate.report.stats.elapsed, timeout);
}

#[test]
fn a_slow_sink_preserves_completed_connect_verdicts_and_latency() {
    let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let timeout = Duration::from_millis(100);
    let sink_delay = Duration::from_millis(150);
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(tcp::SystemProvider, SystemResolver),
    );
    let request = scan::Request {
        targets: Target::Address(Ipv4Addr::LOCALHOST.into()).into(),
        transport: Transport::Tcp,
        tcp_mode: Default::default(),
        shuffle_seed: None,
        tcp_profiles: Default::default(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        ports: vec![
            first.local_addr().unwrap().port(),
            second.local_addr().unwrap().port(),
        ],
        attempts: 1,
        timeout,
        probes_per_second: None,
        max_in_flight: 2,
        limits: scan::Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    };
    let collector = connect::Collector::default();
    let mut sink = collector.clone();
    let mut delayed = false;
    let report = client
        .scan_connect(request, move |event| {
            if !delayed {
                delayed = true;
                std::thread::sleep(sink_delay);
            }
            sink.publish(event)
        })
        .unwrap();
    let aggregate = collector.finish(report).unwrap();
    assert_eq!(aggregate.endpoints.len(), 2);
    for endpoint in &aggregate.endpoints {
        let probe = &endpoint.probes[0];
        assert_eq!(probe.outcome, connect::Outcome::Connected);
        assert_eq!(probe.connect_succeeded, Some(true));
        assert!(probe.elapsed < timeout);
    }
    let stats = aggregate.report.stats;
    assert_eq!(stats.rtt.received, 2);
    assert_eq!(stats.rtt.lost, 0);
    assert!(stats.rtt.max.unwrap() < timeout);
    assert!(stats.elapsed >= sink_delay);
}
