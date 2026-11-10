// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::fuzz::{Request as Campaign, Strategy};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};

use crate::engine::operation::testing;
use crate::fuzz::{Event, Request};

fn request(destination: Ipv4Addr) -> Request {
    let mut packet = Packet::default();
    packet.push(Ipv4 {
        destination,
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 12_345,
        destination_port: 9,
        ..Udp::default()
    });
    let campaign = Campaign {
        cases: 1,
        strategies: vec![Strategy::Boundary],
        limits: packetcraftr_core::fuzz::Limits {
            max_duration: Duration::from_secs(30),
            ..packetcraftr_core::fuzz::Limits::default()
        },
        ..Campaign::default()
    };
    let mut request = Request::new(campaign, packet);
    request.timeout = Duration::from_millis(250);
    request
}

#[test]
fn denied_destination_is_refused_before_transmission() {
    let (client, sends) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let error = client
        .fuzz(request(Ipv4Addr::new(10, 0, 0, 2)), |_: Event| {
            Ok::<(), BoundaryError>(())
        })
        .unwrap_err();
    assert!(matches!(error, super::Error::Authorization(_)), "{error:?}");
    assert_eq!(sends.load(Ordering::Relaxed), 0);
}

#[test]
fn first_event_output_failure_is_returned() {
    let (client, _) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let calls = AtomicUsize::new(0).into();
    let error = client
        .fuzz(
            request(Ipv4Addr::new(10, 0, 0, 1)),
            testing::fail_sink(&calls),
        )
        .unwrap_err();
    assert!(matches!(error, super::Error::Output { .. }), "{error:?}");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn exhausted_deadline_is_returned_before_transmission() {
    let (client, sends) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let client = client.with_deadline(Deadline::new(Duration::ZERO));
    let error = client
        .fuzz(request(Ipv4Addr::new(10, 0, 0, 1)), |_: Event| {
            Ok::<(), BoundaryError>(())
        })
        .unwrap_err();
    assert!(matches!(
        error,
        super::Error::Campaign(packetcraftr_core::fuzz::Error::DurationLimit { .. })
    ));
    assert_eq!(sends.load(Ordering::Relaxed), 0);
}
