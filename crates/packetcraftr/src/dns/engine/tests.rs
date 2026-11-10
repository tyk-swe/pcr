// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::dns::{Event, Limits, QueryType, Request, TransportMode};
use crate::engine::operation::testing;
use crate::target::{Family, Target};

fn request(server: Ipv4Addr) -> Request {
    Request {
        server: Target::Address(IpAddr::V4(server)),
        address_family: Family::Any,
        server_port: 53,
        source_port: 12_345,
        query_name: "example.test".to_owned(),
        query_type: QueryType::A,
        transaction_id: 7,
        recursion_desired: true,
        edns: None,
        transport: TransportMode::Udp,
        attempts: 1,
        timeout: Duration::from_millis(5),
        queries_per_second: None,
        limits: Limits {
            max_duration: Duration::from_secs(1),
            ..Limits::default()
        },
        route: crate::route::Options::default(),
        collection: crate::exchange::Collection::default(),
    }
}

#[test]
fn denied_server_is_refused_before_transmission() {
    let (client, sends) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let error = client
        .dns(request(Ipv4Addr::new(10, 0, 0, 2)), |_: Event| {
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
        .dns(
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
        .dns(request(Ipv4Addr::new(10, 0, 0, 1)), |_: Event| {
            Ok::<(), BoundaryError>(())
        })
        .unwrap_err();
    assert!(
        matches!(error, super::Error::DurationLimit { .. }),
        "{error:?}"
    );
    assert_eq!(sends.load(Ordering::Relaxed), 0);
}
