// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::engine::operation::testing;
use crate::probe::Transport;
use crate::target::{Family, Target};
use crate::traceroute::{Event, Limits, Request};

fn request(target: Ipv4Addr) -> Request {
    Request {
        target: Target::Address(IpAddr::V4(target)),
        strategy: Transport::Udp,
        address_family: Family::Any,
        destination_port: Some(33_434),
        source_port: None,
        payload_size: 0,
        dont_fragment: false,
        dscp: 0,
        first_hop: 1,
        max_hops: 1,
        probes_per_hop: 1,
        timeout: Duration::from_millis(5),
        probes_per_second: None,
        limits: Limits {
            max_duration: Duration::from_secs(1),
            ..Limits::default()
        },
        route: crate::route::Options::default(),
        collection: crate::exchange::Collection::default(),
    }
}

#[test]
fn denied_target_is_refused_before_transmission() {
    let (client, sends) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let error = client
        .traceroute(request(Ipv4Addr::new(10, 0, 0, 2)), |_: Event| {
            Ok::<(), BoundaryError>(())
        })
        .unwrap_err();
    assert!(matches!(error, super::Error::Authorization(_)));
    assert_eq!(sends.load(Ordering::Relaxed), 0);
}

#[test]
fn first_event_output_failure_is_returned() {
    let (client, _) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let calls = AtomicUsize::new(0).into();
    let error = client
        .traceroute(
            request(Ipv4Addr::new(10, 0, 0, 1)),
            testing::fail_sink(&calls),
        )
        .unwrap_err();
    assert!(matches!(error, super::Error::Output { .. }));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn exhausted_deadline_is_returned_before_transmission() {
    let (client, sends) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let client = client.with_deadline(Deadline::new(Duration::ZERO));
    let error = client
        .traceroute(request(Ipv4Addr::new(10, 0, 0, 1)), |_: Event| {
            Ok::<(), BoundaryError>(())
        })
        .unwrap_err();
    assert!(matches!(error, super::Error::DurationLimit { .. }));
    assert_eq!(sends.load(Ordering::Relaxed), 0);
}
