// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use crate::common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr::policy::{DestinationConstraint, Policy};
use packetcraftr::runtime::Runtime;
use packetcraftr::{Client, ProviderSet, exchange, route, send};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::template::Template;
use packetcraftr_netio::interface::{self, Id as InterfaceId};
use packetcraftr_netio::link::Mode;
use packetcraftr_netio::route::{Decision, Error as RouteError, Provider as RouteProvider};

use common::{
    FakeProviders, FixedRoutes, NeverTransmit, RecordingRoutes, RecordingTransmit, SELECTED_SOURCE,
    Step, Steps,
};

const FIRST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SECOND: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
const THIRD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 12);

type RecordingClient = Client<FakeProviders<FixedRoutes, RecordingTransmit>>;

fn client(policy: Policy) -> (RecordingClient, Steps) {
    let (client, steps, _) = recording_client(policy);
    (client, steps)
}

fn recording_client(policy: Policy) -> (RecordingClient, Steps, RecordingTransmit) {
    let steps = Steps::default();
    let io = RecordingTransmit::new(steps.clone());
    let client = Client::new(
        builtin::registry(),
        policy,
        common::providers(FixedRoutes, io.clone()),
    );
    (client, steps, io)
}

fn fully_recorded_client(
    policy: Policy,
) -> (
    Client<FakeProviders<RecordingRoutes, RecordingTransmit>>,
    Steps,
) {
    let steps = Steps::default();
    let mut providers = common::providers(
        RecordingRoutes(steps.clone()),
        RecordingTransmit::new(steps.clone()),
    );
    providers.interface.steps = steps.clone();
    (Client::new(builtin::registry(), policy, providers), steps)
}

fn send_once<P: packetcraftr::PacketProviders>(
    client: &Client<P>,
    packet: Packet,
    options: send::Options,
) -> Result<send::Report, send::Error> {
    client.send(
        send::Request::packet(packet, options),
        send::Collector::default(),
    )
}

fn first_packet(destinations: &[Ipv4Addr]) -> Packet {
    template(destinations)
        .expand(1)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
}

fn template(destinations: &[Ipv4Addr]) -> Template {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: SELECTED_SOURCE,
            destination: destinations[0],
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(b"probe".to_vec()));
    Template::new(packet).axis(
        0,
        "destination",
        destinations
            .iter()
            .map(|destination| FieldValue::Ipv4(*destination))
            .collect(),
    )
}

fn layer2_send() -> send::Options {
    let mut options = send::Options::default();
    options.plan.link_mode = Mode::Layer2;
    options
}

fn exchange_request(template: Template) -> exchange::Request {
    exchange::Request {
        timeout: Duration::from_millis(100),
        ..exchange::Request::new(template, layer2_send())
    }
}

fn neighbor(address: Ipv4Addr) -> Step {
    Step::Neighbor(IpAddr::V4(address))
}

fn is_transmit(step: &Step) -> bool {
    matches!(step, Step::Transmit(_))
}

fn frame_len() -> u64 {
    let (client, _) = client(Policy::default());
    let report = send_once(&client, first_packet(&[FIRST]), layer2_send())
        .expect("one allowed datagram is sent");
    report.stats.bytes
}

fn late_denials() -> [(Policy, &'static str); 2] {
    [
        (
            Policy {
                allowed_destinations: vec![
                    DestinationConstraint::Exact(IpAddr::V4(FIRST)),
                    DestinationConstraint::Exact(IpAddr::V4(SECOND)),
                ],
                ..Policy::default()
            },
            "policy.destination_not_allowed",
        ),
        (
            Policy {
                max_bytes_per_operation: 3 * frame_len() - 1,
                ..Policy::default()
            },
            "policy.byte_limit",
        ),
    ]
}

#[test]
fn xchg_reject_no_disc_traffic() {
    let (client, steps, io) = recording_client(Policy::default());
    let client = client.with_runtime(Runtime::new(0).unwrap());

    let error = client
        .exchange(
            exchange_request(template(&[FIRST])),
            exchange::Collector::default(),
        )
        .expect_err("the runtime has no worker for the sink");

    assert!(matches!(error, exchange::Error::Output { .. }), "{error:?}");
    assert_eq!(
        error.classification().code,
        "internal.progressive_output_worker_exhausted"
    );
    assert_eq!(steps.take(), [], "no ARP request and no transmission");
    assert_eq!(io.armed(), 0, "no discovery capture was armed");
    assert_eq!(client.runtime().snapshot().rejected_admissions, 1);
}

fn by_name() -> send::Options {
    let mut options = layer2_send();
    options.plan.interface = Some(route::Interface::Name("fixture0".to_owned()));
    options
}

fn admission_denials() -> [(Policy, &'static str); 2] {
    [
        (
            Policy {
                max_packets_per_operation: 1,
                ..Policy::default()
            },
            "policy.packet_limit",
        ),
        (
            Policy {
                allowed_destinations: vec![DestinationConstraint::Exact(IpAddr::V4(THIRD))],
                ..Policy::default()
            },
            "policy.destination_not_allowed",
        ),
    ]
}

#[test]
fn admission_precedes_iface_route_nbr_call() {
    for (policy, code) in admission_denials() {
        let (client, steps) = fully_recorded_client(policy.clone());
        let error = client
            .send(
                send::Request::new(template(&[FIRST, SECOND]), by_name()),
                send::Collector::default(),
            )
            .expect_err("send is refused at admission");
        assert_eq!(error.classification().code, code);
        assert_eq!(steps.take(), [], "send {code}: no provider was called");

        let (client, steps) = fully_recorded_client(policy);
        let error = client
            .exchange(
                exchange::Request {
                    send: by_name(),
                    ..exchange_request(template(&[FIRST, SECOND]))
                },
                exchange::Collector::default(),
            )
            .expect_err("exchange is refused at admission");
        assert_eq!(error.classification().code, code);
        assert_eq!(steps.take(), [], "exchange {code}: no provider was called");
    }
}

/// One device the operating system can re-create under a new index. A strict
/// route provider refuses an interface hint it does not know; a lenient one
/// answers with the current device whatever the hint says.
#[derive(Clone)]
struct Replugged {
    index: Arc<AtomicU32>,
    enumerations: Arc<AtomicUsize>,
    strict: bool,
}

impl Replugged {
    fn new(index: u32, strict: bool) -> Self {
        Self {
            index: Arc::new(AtomicU32::new(index)),
            enumerations: Arc::new(AtomicUsize::new(0)),
            strict,
        }
    }

    fn recreate(&self, index: u32) {
        self.index.store(index, Ordering::SeqCst);
    }

    fn enumerations(&self) -> usize {
        self.enumerations.load(Ordering::SeqCst)
    }

    fn current(&self) -> InterfaceId {
        InterfaceId {
            name: "fixture0".to_owned(),
            index: self.index.load(Ordering::SeqCst),
        }
    }
}

impl interface::Provider for Replugged {
    fn interfaces(&self, _deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        self.enumerations.fetch_add(1, Ordering::SeqCst);
        Ok(vec![interface::Info {
            id: self.current(),
            ..common::fixture_interface()
        }])
    }
}

impl RouteProvider for Replugged {
    type Error = RouteError;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        deadline.check_cancelled()?;
        let current = self.current();
        if let Some(hint) = interface_hint
            && self.strict
            && *hint != current
        {
            return Err(RouteError::InterfaceNotFound {
                name: hint.name.clone(),
                index: hint.index,
            });
        }
        let mut decision = FixedRoutes
            .lookup_with_preferences(destination, interface_hint, preferred_source, deadline)
            .expect("fixed routes cannot fail");
        decision.interface = current;
        Ok(decision)
    }
}

fn replugged_client(device: &Replugged) -> Client<impl packetcraftr::PacketProviders> {
    Client::new(
        builtin::registry(),
        Policy::default(),
        ProviderSet::packet(device.clone(), device.clone(), NeverTransmit, NeverTransmit),
    )
}

fn plan_by_name(
    client: &Client<impl packetcraftr::PacketProviders>,
    deadline: &Deadline,
) -> Result<route::Plan, packetcraftr::Error> {
    client.plan(
        &first_packet(&[FIRST]),
        None,
        &route::Options {
            interface: Some(route::Interface::Name("fixture0".to_owned())),
            ..route::Options::default()
        },
        deadline,
    )
}
