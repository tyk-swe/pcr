// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use packetcraftr::{
    Client,
    os::{self, Collector, Outcome, Request},
    policy::Policy,
    route,
    target::Target,
};
use packetcraftr_core::protocol::builtin;
use packetcraftr_netio::link::Mode;

use crate::common::{
    providers,
    responder::{Io, Routes, State},
};

#[test]
fn public_os_workflow_retains_wire_evidence_and_bounded_cleanup() {
    let state = Arc::new(Mutex::new(State {
        os_ports: Some((80, 81)),
        ..State::default()
    }));
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        providers(Routes, Io(Arc::clone(&state))),
    );
    let mut request = Request::new(
        Target::Address("192.0.2.2".parse().unwrap()),
        80,
        81,
        os::builtin_corpus().unwrap(),
    );
    request.attempts = 1;
    request.timeout = Duration::from_millis(10);
    request.route = route::Options {
        link_mode: Mode::Layer3,
        ..Default::default()
    };
    let collector = Collector::default();
    let report = client.identify_os(request, collector.clone()).unwrap();
    let aggregate = collector.finish(report).unwrap();
    assert_eq!(aggregate.report.identification.outcome, Outcome::Unknown);
    assert_eq!(aggregate.report.observations.len(), 3);
    assert_eq!(aggregate.report.stats.packets_attempted, 6);
    assert_eq!(state.lock().unwrap().sends, 6);
    assert!(aggregate.report.complete);
}

#[test]
fn os_policy_refusal_never_arms_capture() {
    let state = Arc::new(Mutex::new(State::default()));
    let mut policy = Policy::default();
    policy
        .allowed_destinations
        .push("198.51.100.0/24".parse().unwrap());
    let client = Client::new(
        builtin::registry(),
        policy,
        providers(Routes, Io(Arc::clone(&state))),
    );
    let request = Request::new(
        Target::Address("192.0.2.2".parse().unwrap()),
        80,
        81,
        os::builtin_corpus().unwrap(),
    );
    assert!(client.identify_os(request, Collector::default()).is_err());
    let state = state.lock().unwrap();
    assert_eq!(state.armed, 0);
    assert_eq!(state.sends, 0);
}
