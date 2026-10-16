// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Composes local route and recording-I/O providers with an explicit
//! destination policy and finite budgets. No network traffic is sent.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use packetcraftr::policy::{DestinationConstraint, Policy};
use packetcraftr::{Client, ProviderSet, send};
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
use packetcraftr_netio::{interface, transmit};

const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 5);

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
        expression::Limits::default(),
    )
}

#[test]
fn public_provider_composition() -> Result<(), Box<dyn std::error::Error>> {
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
    let providers = ProviderSet::packet(
        DocumentationRoutes,
        interface::SystemProvider,
        sender.clone(),
        sender,
    ).with_resolver(packetcraftr::target::SystemResolver);
    let client = Client::new(builtin::registry(), policy, providers);

    let options = send::Options {
        plan: packetcraftr::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer3,
            ..Default::default()
        },
        ..Default::default()
    };

    let allowed = packet(Ipv4Addr::new(192, 0, 2, 99))?;
    let collector = send::Collector::default();
    let report = client.send(
        send::Request::packet(allowed, options.clone()),
        collector.clone(),
    )?;
    let sent = collector.finish(report)?;
    println!(
        "sent {} bytes to an allowed destination",
        sent.stats.bytes
    );

    let outside = packet(Ipv4Addr::new(198, 51, 100, 1))?;
    match client.send(
        send::Request::packet(outside, options),
        send::Collector::default(),
    ) {
        Err(error) => println!("denied outside the allowlist: {error}"),
        Ok(_) => unreachable!("the allowlist must reject other destinations"),
    }
    assert_eq!(recorded.lock().expect("sent lock").len(), 1);
    // Public OS requests validate and authorize before any provider activity.
    let mut os_request = packetcraftr::os::Request::new(
        packetcraftr::target::Target::Address(Ipv4Addr::new(198, 51, 100, 1).into()),
        80, 81, packetcraftr::os::builtin_corpus()?,
    );
    os_request.attempts = 1;
    os_request.limits.max_probes = 7;
    assert!(matches!(client.identify_os(os_request, packetcraftr::os::Collector::default()),
        Err(packetcraftr::os::Error::Authorization(_))));
    assert_eq!(recorded.lock().expect("sent lock").len(), 1);
    Ok(())
}

// This backend deliberately implements transmission alone. The detached crate
// must compile and perform an authorized numeric send without capture stubs.
struct TransmitOnly(RecordingSender);

impl transmit::Provider for TransmitOnly {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        self.0.send(frame)
    }
}

#[test]
fn numeric_layer3_without_capture_capability() -> Result<(), Box<dyn std::error::Error>> {
    let recorded = RecordingSender::default();
    let client = Client::new(
        builtin::registry(),
        Policy {
            allowed_destinations: vec![DestinationConstraint::Network(
                packetcraftr::target::Network::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)?,
            )],
            max_packets_per_operation: 1,
            max_bytes_per_operation: 1_500,
            ..Policy::default()
        },
        ProviderSet::transmit(DocumentationRoutes, interface::SystemProvider, TransmitOnly(recorded.clone())),
    );
    let collector = send::Collector::default();
    let report = client.send_layer3(
        send::Request::packet(packet(Ipv4Addr::new(192, 0, 2, 99))?, send::Options::default()),
        collector.clone(),
    )?;
    let result = collector.finish(report)?;
    assert_eq!(result.stats.packets_completed, 1);
    assert_eq!(recorded.sent.lock().unwrap().len(), 1);
    Ok(())
}
