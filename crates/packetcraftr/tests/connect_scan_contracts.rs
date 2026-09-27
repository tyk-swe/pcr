// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Native TCP connect admission is process-wide, so these contracts run in
//! their own test binary rather than beside other connect tests.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use packetcraftr::policy::Policy;
use packetcraftr::probe::Transport;
use packetcraftr::scan::{self, connect};
use packetcraftr::target::{Family, SystemResolver, Target};
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{Classified as _, Kind};
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

fn request() -> scan::Request {
    scan::Request {
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
    }
}

#[test]
fn timed_out_attempts_still_releasing_admission_do_not_fail_the_scan() {
    let request = request();
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

#[test]
fn route_overrides_are_rejected_before_any_tcp_connect() {
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

    let calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet {
            route: route::SystemProvider,
            interface: interface::SystemProvider,
            capture: capture::SystemProvider,
            transmit: transmit::SystemProvider,
            tcp: CountConnects(Arc::clone(&calls)),
            resolver: SystemResolver,
        },
    );
    let request = scan::Request {
        ports: vec![80],
        max_in_flight: 1,
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
