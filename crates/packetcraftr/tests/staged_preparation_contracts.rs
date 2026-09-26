// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Staged preparation keeps authorization ahead of neighbor discovery and the
//! final check ahead of transmission, in both of its orders.

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use packetcraftr::clock::SystemClock;
use packetcraftr::fuzz::{self, LiveOptions, RunInput};
use packetcraftr::policy::{Authorizer, DestinationConstraint, Operation, Policy};
use packetcraftr::probe::ExchangeExecutor;
use packetcraftr::{Client, exchange, send};
use packetcraftr_core::error::{BoundaryError, Classified};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::template::Template;
use packetcraftr_netio::link::Mode;

use common::{FixedRoutes, NEIGHBOR_MAC, RecordingTransmit, SELECTED_SOURCE, Step, Steps};

const FIRST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SECOND: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
const THIRD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 12);

type RecordingClient = Client<FixedRoutes, RecordingTransmit>;

fn client(policy: Policy) -> (RecordingClient, Steps) {
    let (client, steps, _) = recording_client(policy);
    (client, steps)
}

/// A client over recording I/O, the steps it records, and a handle on that
/// I/O for counting capture sessions.
fn recording_client(policy: Policy) -> (RecordingClient, Steps, RecordingTransmit) {
    let steps = Steps::default();
    let io = RecordingTransmit::new(steps.clone());
    let client = Client::new(builtin::registry(), FixedRoutes, io.clone(), policy);
    (client, steps, io)
}

/// One UDP datagram per destination, framed at Layer 2 so each needs its
/// neighbor's MAC address.
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

fn exchange_options() -> exchange::Options {
    exchange::Options {
        timeout: Duration::from_millis(100),
        send: layer2_send(),
        ..exchange::Options::default()
    }
}

fn neighbor(address: Ipv4Addr) -> Step {
    Step::Neighbor(IpAddr::V4(address))
}

fn is_transmit(step: &Step) -> bool {
    matches!(step, Step::Transmit(_))
}

/// The exact wire size of one datagram from [`template`].
fn frame_len() -> u64 {
    let (client, _) = client(Policy::default());
    let report = client
        .send(
            template(&[FIRST])
                .expand(1)
                .unwrap()
                .next()
                .unwrap()
                .unwrap(),
            layer2_send(),
        )
        .expect("one allowed datagram is sent");
    report.stats.bytes
}

/// Policies under which the first two datagrams pass and the third is denied
/// by a later check: its destination, then the cumulative byte budget.
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
fn a_policy_rejected_packet_causes_no_neighbor_discovery_traffic() {
    let policy = Policy {
        allowed_destinations: vec![DestinationConstraint::Exact(IpAddr::V4(SECOND))],
        ..Policy::default()
    };
    let (client, steps, io) = recording_client(policy);
    let packet = template(&[FIRST])
        .expand(1)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();

    let error = client
        .send(packet, layer2_send())
        .expect_err("the destination is outside the allowlist");

    assert_eq!(
        error.classification().code,
        "policy.destination_not_allowed"
    );
    assert_eq!(steps.take(), [], "no ARP request and no transmission");
    assert_eq!(io.armed(), 0, "no discovery capture was armed");
}

#[test]
fn exchange_discovers_neighbors_only_after_every_packet_is_admitted() {
    let (client, steps) = client(Policy::default());
    client
        .exchange(&template(&[FIRST, SECOND]), exchange_options())
        .expect("an allowed exchange completes");

    let steps = steps.take();
    assert_eq!(steps[..2], [neighbor(FIRST), neighbor(SECOND)]);
    assert_eq!(steps.len(), 4, "{steps:?}");
    assert!(steps[2..].iter().all(is_transmit), "{steps:?}");
}

#[test]
fn a_late_exchange_denial_triggers_no_neighbor_discovery() {
    for (policy, code) in late_denials() {
        let (client, steps) = client(policy);
        let error = client
            .exchange(&template(&[FIRST, SECOND, THIRD]), exchange_options())
            .expect_err("the third packet is denied");

        assert_eq!(error.classification().code, code);
        assert_eq!(steps.take(), [], "{code}: no discovery and no transmission");
    }
}

#[test]
fn a_streamed_set_authorizes_each_packet_before_its_own_discovery() {
    for (policy, code) in late_denials() {
        let (client, steps) = client(policy);
        let published = steps.clone();
        let options = send::SetOptions {
            send: layer2_send(),
            ..send::SetOptions::default()
        };
        let error = client
            .send_set_with_events(&template(&[FIRST, SECOND, THIRD]), options, |frame| {
                published.push(Step::Published(usize::try_from(frame.index).unwrap()));
                Ok(())
            })
            .expect_err("the third packet is denied");

        assert_eq!(error.classification().code, code);
        let steps = steps.take();
        assert_eq!(steps.len(), 6, "{code}: {steps:?}");
        assert_eq!(steps[0], neighbor(FIRST), "{code}");
        assert!(is_transmit(&steps[1]), "{code}: {steps:?}");
        assert_eq!(steps[2], Step::Published(0), "{code}");
        assert_eq!(steps[3], neighbor(SECOND), "{code}");
        assert!(is_transmit(&steps[4]), "{code}: {steps:?}");
        assert_eq!(steps[5], Step::Published(1), "{code}");
    }
}

/// Leaves every decision to the client's own policy.
struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize_operation(&mut self, _operation: Operation<'_>) -> Result<(), BoundaryError> {
        Ok(())
    }
}

#[test]
fn fuzz_accepts_exactly_the_bytes_its_executor_prepared_and_transmitted() {
    let (client, steps) = client(Policy::default());
    let mut executor = ExchangeExecutor::new(&client, exchange_options());
    let request = packet_fuzz::Request {
        cases: 2,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw payload target")],
        ..packet_fuzz::Request::default()
    };
    // No source address and no link header: preparation fills in the route's
    // source, synthesizes Ethernet, and rebuilds with the resolved neighbor.
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            destination: FIRST,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(b"probe".to_vec()));

    let report = fuzz::run(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(100),
                ..LiveOptions::default()
            },
            packet,
            registry: builtin::registry(),
        },
        &mut AllowAll,
        &mut executor,
        &mut SystemClock,
    )
    .expect("the executor's prepared bytes are the expected exact bytes");

    let transmitted = steps
        .take()
        .into_iter()
        .filter_map(|step| match step {
            Step::Transmit(bytes) => Some(bytes),
            Step::Neighbor(_) | Step::Published(_) => None,
        })
        .collect::<Vec<_>>();
    let recorded = report
        .cases
        .iter()
        .map(|case| {
            case.sent
                .as_ref()
                .expect("every case is sent")
                .bytes()
                .to_vec()
        })
        .collect::<Vec<_>>();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded, transmitted);
    for frame in &recorded {
        assert_eq!(frame[..6], NEIGHBOR_MAC.0, "resolved destination MAC");
    }
}
