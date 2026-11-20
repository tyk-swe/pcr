// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::engine::operation::testing;
use crate::os::{Event, Request, builtin_corpus};
use crate::target::Target;

fn request(target: Ipv4Addr) -> Request {
    let mut request = Request::new(
        Target::Address(IpAddr::V4(target)),
        80,
        81,
        builtin_corpus().expect("builtin corpus"),
    );
    request.attempts = 1;
    request.timeout = Duration::from_millis(250);
    request.limits.max_duration = Duration::from_secs(30);
    request
}

#[test]
fn denied_target_is_refused_before_transmission() {
    let (client, sends) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let error = client
        .identify_os(request(Ipv4Addr::new(10, 0, 0, 2)), |_: Event| {
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
        .identify_os(
            request(Ipv4Addr::new(10, 0, 0, 1)),
            testing::fail_sink(&calls),
        )
        .unwrap_err();
    assert!(matches!(error, super::Error::Output(_)), "{error:?}");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn exhausted_deadline_is_returned_before_transmission() {
    let (client, sends) = testing::client(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let client = client.with_deadline(Deadline::new(Duration::ZERO));
    let error = client
        .identify_os(request(Ipv4Addr::new(10, 0, 0, 1)), |_: Event| {
            Ok::<(), BoundaryError>(())
        })
        .unwrap_err();
    assert!(matches!(error, super::Error::Deadline(_)), "{error:?}");
    assert_eq!(sends.load(Ordering::Relaxed), 0);
}
