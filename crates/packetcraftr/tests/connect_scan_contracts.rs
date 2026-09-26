// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native TCP connect admission is process-wide, so these contracts run in
//! their own test binary rather than beside other connect tests.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use packetcraftr::policy::Policy;
use packetcraftr::probe::Transport;
use packetcraftr::scan::{self, connect};
use packetcraftr::target::{Family, SystemResolver, Target};
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp::{MAX_PENDING_CONNECTIONS, Provider, Stream};
use packetcraftr_netio::{capture, interface, route, transmit};

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

/// A silent host, returning a little after the bound it was given, as a
/// system connect may.
struct Silent;

impl Provider for Silent {
    type Stream = Socket;
    fn connect(
        &self,
        _: SocketAddr,
        deadline: &Deadline,
    ) -> Result<Socket, packetcraftr_netio::tcp::Error> {
        let timeout = deadline.remaining().unwrap_or_default();
        std::thread::sleep(timeout + Duration::from_millis(30));
        Err(io::Error::from(io::ErrorKind::TimedOut).into())
    }
}

/// Attempts cancelled at their deadline keep their native admission until the
/// provider call returns, so refilling every slot at once must wait for it
/// instead of failing the whole scan.
#[test]
fn timed_out_attempts_still_releasing_admission_do_not_fail_the_scan() {
    let request = scan::Request {
        targets: Target::Address("192.0.2.10".parse().unwrap()).into(),
        transport: Transport::Tcp,
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        ports: (1..=32).collect(),
        attempts: 1,
        timeout: Duration::from_millis(50),
        probes_per_second: None,
        max_in_flight: MAX_PENDING_CONNECTIONS,
        limits: scan::Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    };
    // Connect scans reach only the TCP provider.
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet {
            route: route::SystemProvider,
            interface: interface::SystemProvider,
            capture: capture::SystemProvider,
            transmit: transmit::SystemProvider,
            tcp: Silent,
            resolver: SystemResolver,
        },
    );
    let collector = connect::Collector::default();
    let report = client
        .scan_connect(request, collector.clone())
        .expect("capacity held by cancelled attempts is waited for");
    let aggregate = collector.finish(report).unwrap();
    let probes = aggregate
        .endpoints
        .iter()
        .flat_map(|endpoint| &endpoint.probes)
        .collect::<Vec<_>>();
    assert_eq!(probes.len(), 32);
    assert!(probes.iter().all(|probe| probe.connect_succeeded.is_none()));
}
