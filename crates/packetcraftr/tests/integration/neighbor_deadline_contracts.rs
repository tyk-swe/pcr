// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr::{Client, neighbor, policy};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_netio::Error as LiveIoError;
use packetcraftr_netio::link::Mode;
use packetcraftr_netio::{capture, transmit};

use crate::common;

use common::clock::VirtualClock;
use common::{FixedRoutes, SELECTED_SOURCE};

#[derive(Clone, Default)]
struct SilentLink {
    waits: Arc<Mutex<Vec<Duration>>>,
    requested_waits: Arc<Mutex<Vec<Duration>>>,
    clock: VirtualClock,
}

impl transmit::Provider for SilentLink {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        let bytes = frame.bytes();
        Ok(transmit::Submission::start().complete(bytes.len(), bytes.clone()))
    }
}

impl capture::Provider for SilentLink {
    type Capture = SilentCapture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, LiveIoError> {
        Ok(SilentCapture {
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: packetcraftr_core::frame::LinkType::ETHERNET,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
            waits: Arc::clone(&self.waits),
            requested_waits: Arc::clone(&self.requested_waits),
            clock: self.clock.clone(),
        })
    }
}

struct SilentCapture {
    metadata: capture::Metadata,
    waits: Arc<Mutex<Vec<Duration>>>,
    requested_waits: Arc<Mutex<Vec<Duration>>>,
    clock: VirtualClock,
}

impl capture::Session for SilentCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), LiveIoError> {
        let timeout = deadline.remaining().unwrap_or_default();
        self.waits.lock().unwrap().push(timeout);
        self.requested_waits.lock().unwrap().push(deadline.limit());
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        let timeout = deadline.remaining().unwrap_or_default();
        self.waits.lock().unwrap().push(timeout);
        let limit = deadline.limit();
        self.requested_waits.lock().unwrap().push(limit);
        if !limit.is_zero() {
            // Charge the requested wait even if real scheduling spent this child deadline.
            self.clock.advance(limit);
        }
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

fn template() -> packetcraftr_core::template::Template {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: SELECTED_SOURCE,
            destination: Ipv4Addr::new(192, 0, 2, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"probe")));
    packetcraftr_core::template::Template::new(packet)
}

#[test]
fn nbr_disc_bounded_by_xchg_dl() {
    let link = SilentLink::default();
    // Each discovery attempt alone may wait far longer than the exchange.
    let attempt_timeout = Duration::from_secs(30);
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy::Policy::default(),
        common::providers(FixedRoutes, link.clone()),
    )
    // Preparation scheduling must not spend the window this fixture gives discovery.
    .with_clock(link.clock.clone())
    .with_neighbor_options(neighbor::Options {
        attempt_timeout,
        ..neighbor::Options::default()
    })
    .expect("bounded neighbor options");
    let timeout = Duration::from_millis(200);
    let mut send = packetcraftr::send::Options::default();
    send.plan.link_mode = Mode::Layer2;
    let request = packetcraftr::exchange::Request {
        timeout,
        ..packetcraftr::exchange::Request::new(template(), send)
    };

    let started = Instant::now();
    let _error = client
        .exchange(request, packetcraftr::exchange::Collector::default())
        .expect_err("no neighbor answers on the silent link");
    let elapsed = started.elapsed();

    let waits = link.waits.lock().unwrap();
    assert!(!waits.is_empty(), "discovery waited on its capture");
    let requested_waits = link.requested_waits.lock().unwrap();
    assert!(
        requested_waits.iter().all(|limit| *limit <= timeout),
        "every requested wait is clipped to the exchange deadline: {requested_waits:?}"
    );
    assert!(
        waits.iter().all(|wait| *wait <= timeout),
        "every wait is clipped to the exchange deadline: {waits:?}"
    );
    assert!(elapsed < attempt_timeout / 2, "{elapsed:?}");
}

#[test]
fn a_scans_neighbor_wait_is_measured_by_the_clients_clock() {
    use packetcraftr::scan;
    use packetcraftr::target::{Family, Selection, Target};

    let link = SilentLink::default();
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy::Policy::default(),
        common::providers(FixedRoutes, link.clone()),
    )
    .with_clock(link.clock.clone());
    let timeout = Duration::from_millis(200);
    let request = scan::Request {
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: Selection::from(Target::Address("192.0.2.10".parse().unwrap())),
        address_family: Family::Any,
        endpoints: Vec::new(),
        discovery: scan::discovery::Options {
            mode: scan::discovery::Mode::Only,
            probes: vec![packetcraftr::probe::ProbeEndpoint::Icmp],
            ..scan::discovery::Options::default()
        },
        attempts: 1,
        adaptive: None,
        timeout,
        probes_per_second: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        limits: scan::Limits {
            max_duration: Duration::from_secs(3),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer2,
            ..Default::default()
        },
        collection: packetcraftr::exchange::Collection::default(),
    };

    let report = client
        .scan(request, scan::Collector::default())
        .expect("a silent neighbor leaves its host unresponsive");
    assert_eq!(report.stats.packets_attempted, 1);
    assert!(
        // The capture's waits approach the attempt timeout on that clock,
        // however little wall time they took.
        report.stats.elapsed >= timeout * 9 / 10,
        "the wait the client's clock saw is reported: {:?}",
        report.stats.elapsed
    );
}
