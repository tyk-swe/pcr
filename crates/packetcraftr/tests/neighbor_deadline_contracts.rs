// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The operation deadline bounds neighbor discovery, the one preparation step
//! that waits on the network, rather than being checked only after it.

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

mod common;

use common::{FixedRoutes, SELECTED_SOURCE};

/// I/O on a link where no neighbor ever answers. It confirms every send, and
/// each capture wait records its timeout and then waits all of it out.
#[derive(Clone, Default)]
struct SilentLink {
    waits: Arc<Mutex<Vec<Duration>>>,
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
        })
    }
}

struct SilentCapture {
    metadata: capture::Metadata,
    waits: Arc<Mutex<Vec<Duration>>>,
}

impl capture::Session for SilentCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), LiveIoError> {
        let timeout = deadline.remaining().unwrap_or_default();
        self.waits.lock().unwrap().push(timeout);
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        let timeout = deadline.remaining().unwrap_or_default();
        self.waits.lock().unwrap().push(timeout);
        std::thread::sleep(timeout);
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
fn neighbor_discovery_is_bounded_by_the_exchange_deadline() {
    let link = SilentLink::default();
    // Each discovery attempt alone may wait far longer than the exchange.
    let attempt_timeout = Duration::from_secs(30);
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        FixedRoutes,
        link.clone(),
        policy::Policy::default(),
    )
    .with_neighbor_options(neighbor::Options {
        attempt_timeout,
        ..neighbor::Options::default()
    })
    .expect("bounded neighbor options");
    let timeout = Duration::from_millis(200);
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
        .expect_err("no neighbor answers on the silent link");
    let elapsed = started.elapsed();

    let waits = link.waits.lock().unwrap();
    assert!(!waits.is_empty(), "discovery waited on its capture");
    assert!(
        waits.iter().all(|wait| *wait <= timeout),
        "every wait is clipped to the exchange deadline: {waits:?}"
    );
    assert!(elapsed < attempt_timeout / 2, "{elapsed:?}");
}
