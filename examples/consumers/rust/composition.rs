// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Composes local route and recording-I/O providers with an explicit
//! destination policy and finite budgets. No network traffic is sent.
//!
//! Production uses each capability's `SystemProvider`, joined by `PacketIo`,
//! under the same policy contract; the client resolves neighbors over that
//! I/O itself. Run with scripts/check-external-consumer.py.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use packetcraftr::Client;
use packetcraftr::policy::{DestinationConstraint, Policy};
use packetcraftr::send;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::expression;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_core::protocol::builtin;
use packetcraftr_netio::Error as LiveIoError;
use packetcraftr_netio::capture;
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Capability;
use packetcraftr_netio::route::{Decision, Provider, Scope, SelectionReason};
use packetcraftr_netio::transmit;

/// The documentation source this composition's route selects.
const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);

/// On-link route provider with one dual-capability Ethernet interface.
struct DocumentationRoutes;

impl Provider for DocumentationRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        Ok(Decision {
            interface: InterfaceId {
                name: "example0".to_owned(),
                index: 1,
            },
            source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
            selected_source: Some(IpAddr::V4(SELECTED_SOURCE)),
            preferred_source: None,
            next_hop: Some(destination),
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Global,
            mtu: 1_500,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        })
    }
}

/// Retains submitted bytes for inspection without transmitting them.
#[derive(Clone, Default)]
struct RecordingSender {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl transmit::Provider for RecordingSender {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        self.sent
            .lock()
            .expect("sent lock")
            .push(frame.bytes().to_vec());
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

impl capture::Provider for RecordingSender {
    type Capture = capture::SystemSession;

    /// The client arms capture only to resolve a neighbor; this example's
    /// Layer 3 sends never need one, so arming would prove the wiring wrong.
    fn arm_capture(
        &self,
        _request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, LiveIoError> {
        unreachable!("Layer 3 sends never resolve neighbors")
    }
}

fn packet(destination: Ipv4Addr) -> Result<packetcraftr_core::packet::Packet, expression::Error> {
    expression::parse(
        &format!(
            "ipv4(src={SELECTED_SOURCE},dst={destination})/udp(sport=12345,dport=9)/raw(text=ping)"
        ),
        &builtin::registry(),
        expression::Options::default(),
    )
}

#[test]
fn public_provider_composition() -> Result<(), Box<dyn std::error::Error>> {
    // Allow only TEST-NET-1, with an 8-packet / 16 KiB per-operation budget
    // enforced before provider calls.
    let policy = Policy {
        allowed_destinations: vec![DestinationConstraint::Network(
            packetcraftr::target::Network::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)?,
        )],
        max_packets_per_operation: 8,
        max_bytes_per_operation: 16 * 1024,
        ..Policy::default()
    };

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sender = RecordingSender {
        sent: Arc::clone(&recorded),
    };
    let client = Client::new(builtin::registry(), DocumentationRoutes, sender, policy);

    // Layer 3 planning skips neighbor resolution entirely, so the composed
    // client never arms capture on the recording I/O.
    let options = send::Options {
        plan: packetcraftr::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer3,
            ..Default::default()
        },
        ..Default::default()
    };

    let allowed = packet(Ipv4Addr::new(192, 0, 2, 99))?;
    let report = client.send(allowed, options.clone())?;
    println!(
        "sent {} bytes to an allowed destination",
        report.sent.bytes_sent()
    );

    let outside = packet(Ipv4Addr::new(198, 51, 100, 1))?;
    match client.send(outside, options) {
        Err(error) => println!("denied outside the allowlist: {error}"),
        Ok(_) => unreachable!("the allowlist must reject other destinations"),
    }
    assert_eq!(recorded.lock().expect("sent lock").len(), 1);
    Ok(())
}
