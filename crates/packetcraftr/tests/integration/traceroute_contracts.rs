// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::responder::{Io, Routes, State};
use packetcraftr::policy::{DestinationConstraint, Policy};
use packetcraftr::probe::Transport;
use packetcraftr::target::{Family, Target};
use packetcraftr::{Client, traceroute};
use packetcraftr_core::error::Classified;
use packetcraftr_netio::link::Mode;

const DESTINATION: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

fn network() -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State {
        hops: Some(3),
        ..State::default()
    }))
}

fn client(state: &Arc<Mutex<State>>, policy: Policy) -> Client<common::FakeProviders<Routes, Io>> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        common::providers(Routes, Io(Arc::clone(state))),
    )
}

fn request() -> traceroute::Request {
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 1500;
    traceroute::Request {
        target: Target::Address(IpAddr::V4(DESTINATION)),
        strategy: Transport::Tcp,
        address_family: Family::Any,
        destination_port: Some(80),
        source_port: None,
        payload_size: 0,
        dont_fragment: false,
        dscp: 0,
        first_hop: 1,
        max_hops: 5,
        probes_per_hop: 1,
        timeout: Duration::from_millis(200),
        probes_per_second: None,
        limits: traceroute::Limits {
            max_duration: Duration::from_secs(5),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection,
    }
}

#[test]
fn denied_dst_arms_no_capture_sends_nothing() {
    let state = network();
    let policy = Policy {
        allowed_destinations: vec![DestinationConstraint::Exact(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 99,
        )))],
        ..Policy::default()
    };

    let error = client(&state, policy)
        .traceroute(request(), |_| Ok(()))
        .expect_err("the destination is outside the allowed set");

    assert!(
        matches!(error, traceroute::Error::Authorization(_)),
        "{error}"
    );
    let state = state.lock().unwrap();
    assert_eq!(state.armed, 0);
    assert_eq!(state.sends, 0);
}

fn narrowed_request(frames: usize, bytes: usize) -> traceroute::Request {
    let mut request = request();
    request.limits.evidence.max_frames = frames;
    request.limits.evidence.max_undecoded = frames;
    request.limits.evidence.max_bytes = bytes;
    request
}

#[test]
fn wide_collection_reject_before_capture() {
    let bytes = traceroute::Limits::default().evidence.max_bytes;
    let frames = traceroute::Limits::default().evidence.max_frames;
    for (request, field) in [
        (narrowed_request(16, bytes), "capture_max_frames"),
        (narrowed_request(frames, 1 << 20), "capture_max_bytes"),
    ] {
        let state = network();

        let error = client(&state, Policy::default())
            .traceroute(request, |_| Ok(()))
            .expect_err("the collection captures more than the evidence limits retain");

        assert!(
            matches!(&error, traceroute::Error::InvalidLimit { field: named, .. } if *named == field),
            "{error}"
        );
        assert_eq!(error.classification().code, "cli.traceroute_limit");
        let state = state.lock().unwrap();
        assert_eq!(state.armed, 0);
        assert_eq!(state.sends, 0);
    }
}
