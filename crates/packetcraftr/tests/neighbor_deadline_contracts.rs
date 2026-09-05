// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! The operation deadline bounds neighbor discovery, the one preparation step
//! that waits on the network, rather than being checked only after it.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr::core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr::core::{Packet, layer::Raw};
use packetcraftr::netio::link::Mode;
use packetcraftr::netio::{capture, neighbor};
use packetcraftr::{Client, policy};

mod support;

use support::{FixedRoutes, NeverTransmit, SELECTED_SOURCE};

/// A resolver that records the propagated deadline and immediately refuses discovery.
#[derive(Default)]
struct DeadlineBoundNeighbors {
    deadline: Arc<Mutex<Option<Instant>>>,
}

impl neighbor::Resolver for DeadlineBoundNeighbors {
    fn resolve(
        &self,
        request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        let deadline = request
            .deadline
            .expect("bounded exchanges must hand the resolver their deadline");
        *self.deadline.lock().unwrap() = Some(deadline);
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

fn template() -> packetcraftr::core::template::Template {
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
    packetcraftr::core::template::Template::new(packet)
}

#[test]
fn neighbor_discovery_is_bounded_by_the_exchange_deadline() {
    let deadline = Arc::new(Mutex::new(None));
    let client = Client::new(
        packetcraftr::core::protocol::builtin::registry(),
        FixedRoutes,
        DeadlineBoundNeighbors {
            deadline: Arc::clone(&deadline),
        },
        NeverTransmit,
        policy::Policy::default(),
    );
    let timeout = Duration::from_secs(30);
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
    let _error = client
        .exchange(&template(), options)
        .expect_err("scripted discovery refuses the neighbor");
    let finished = Instant::now();

    let deadline = deadline
        .lock()
        .unwrap()
        .expect("the resolver received the exchange deadline");
    assert!(deadline >= started + timeout);
    assert!(deadline <= finished + timeout);
}
