// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! The operation deadline bounds neighbor discovery, the one preparation step
//! that waits on the network, rather than being checked only after it.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr::core::error::Classified;
use packetcraftr::core::frame::LinkType;
use packetcraftr::core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr::core::{Packet, layer::Raw};
use packetcraftr::netio::capture;
use packetcraftr::netio::interface::Id as InterfaceId;
use packetcraftr::netio::link::{Capability, MacAddress, Mode};
use packetcraftr::netio::neighbor;
use packetcraftr::netio::route::{Decision, Provider, Scope, SelectionReason};
use packetcraftr::netio::transmit;
use packetcraftr::{Client, policy};

const INTERFACE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

struct OnLinkEthernetRoutes;

impl Provider for OnLinkEthernetRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        Ok(Decision {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            source_mac: Some(INTERFACE_MAC),
            selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Private,
            mtu: 1_500,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        })
    }
}

/// A resolver that, like the real one, only gives up when the request deadline
/// arrives, and records the deadline it was handed.
#[derive(Default)]
struct DeadlineBoundNeighbors {
    deadlines: Arc<Mutex<Vec<Option<Instant>>>>,
}

impl neighbor::Resolver for DeadlineBoundNeighbors {
    fn resolve(
        &self,
        request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        self.deadlines.lock().unwrap().push(request.deadline);
        let deadline = request
            .deadline
            .expect("bounded exchanges must hand the resolver their deadline");
        if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            std::thread::sleep(remaining);
        }
        Err(neighbor::Error::NotFound {
            interface: request.interface.name.clone(),
            target: request.target,
            attempts: 1,
            captured: Vec::new(),
            evidence_truncated: false,
            capture_statistics: capture::Statistics::default(),
        })
    }
}

/// Capture is armed before routes are materialized, so it must exist; it
/// simply never observes anything. Transmission must never be reached.
struct QuietIo;

impl transmit::Sender for QuietIo {
    fn send(
        &self,
        _frame: transmit::Frame<'_>,
    ) -> Result<transmit::Report, packetcraftr::netio::Error> {
        unreachable!("an unresolved neighbor must not reach transmission")
    }
}

impl capture::Provider for QuietIo {
    type Capture = QuietCapture;

    fn arm_capture(
        &self,
        request: &capture::Request,
    ) -> Result<Self::Capture, packetcraftr::netio::Error> {
        Ok(QuietCapture(capture::Metadata {
            interface: request.interface.clone(),
            link_type: LinkType::ETHERNET,
            snap_length: request.limits.snap_length,
        }))
    }
}

struct QuietCapture(capture::Metadata);

impl capture::Session for QuietCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.0
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), packetcraftr::netio::Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<capture::Captured>, packetcraftr::netio::Error> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), packetcraftr::netio::Error> {
        Ok(())
    }

    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

fn template() -> packetcraftr::core::template::Template {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"probe")));
    packetcraftr::core::template::Template::new(packet)
}

#[test]
fn neighbor_discovery_is_bounded_by_the_exchange_deadline() {
    let deadlines = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        packetcraftr::core::protocol::builtin::registry(),
        OnLinkEthernetRoutes,
        DeadlineBoundNeighbors {
            deadlines: Arc::clone(&deadlines),
        },
        QuietIo,
        policy::Policy::default(),
    );
    let timeout = Duration::from_millis(50);
    // An IP-rooted packet on a dual-capability link defaults to Layer 3;
    // Layer 2 framing is what needs the neighbor's MAC address.
    let mut send = packetcraftr::send::Options::default();
    send.plan.link_mode = Mode::Layer2;
    let options = packetcraftr::exchange::Options {
        timeout,
        send,
        ..packetcraftr::exchange::Options::default()
    };

    let started = Instant::now();
    let error = client
        .exchange(&template(), options)
        .expect_err("discovery cannot finish inside the exchange deadline");
    let elapsed = started.elapsed();

    assert_eq!(
        error.classification().code,
        "io.deadline_exceeded",
        "{error}"
    );
    assert!(
        elapsed < timeout * 4,
        "the exchange returned after {elapsed:?}, long after its {timeout:?} deadline"
    );
    let deadline =
        deadlines.lock().unwrap()[0].expect("the resolver received the exchange deadline");
    assert!(deadline <= started + timeout + Duration::from_millis(5));
}
