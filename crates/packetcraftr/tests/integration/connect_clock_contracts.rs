// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use std::io;
use std::net::SocketAddr;
use std::sync::{Mutex, mpsc};
use std::time::Duration;

use packetcraftr::policy::Policy;
use packetcraftr::scan::{self, connect};
use packetcraftr::target::{Family, SystemResolver, Target};
use packetcraftr::{Client, ProviderSet};
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
fn attempt_expires_clock_before_operation_dl() {
    let (release, blocked) = mpsc::channel();
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(Blocked(Mutex::new(blocked)), SystemResolver),
    )
    .with_clock(VirtualClock::default());
    let timeout = Duration::from_millis(20);
    let request = scan::Request {
        target_sources: Vec::new(),
        targets: Target::Address("192.0.2.10".parse().unwrap()).into(),
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        endpoints: vec![packetcraftr::probe::ProbeEndpoint::Tcp { port: 53 }],
        discovery: Default::default(),
        attempts: 1,
        adaptive: None,
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
