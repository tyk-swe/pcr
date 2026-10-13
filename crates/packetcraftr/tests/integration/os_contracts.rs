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

#[test]
fn cached_layer2_neighbor_needs_no_discovery_capture_minimum() {
    let steps = crate::common::Steps::default();
    let io = crate::common::RecordingTransmit::new(steps.clone());
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        providers(
            crate::common::discovery::Routes {
                layer2: true,
                routed: false,
            },
            io,
        ),
    );
    let target = "192.0.2.2".parse().unwrap();
    let mut packet = packetcraftr_core::packet::Packet::new();
    packet.push(packetcraftr_core::protocol::network::Ipv4 {
        destination: target,
        ..Default::default()
    });
    packet.push(packetcraftr_core::protocol::transport::Udp::default());
    let mut options = packetcraftr::send::Options::default();
    options.plan.link_mode = Mode::Layer2;
    client
        .send(
            packetcraftr::send::Request::packet(packet, options),
            packetcraftr::send::Collector::default(),
        )
        .unwrap();
    let mut request = Request::new(
        Target::Address(target.into()),
        80,
        81,
        os::builtin_corpus().unwrap(),
    );
    request.route.link_mode = Mode::Layer2;
    request.attempts = 1;
    request.timeout = Duration::from_millis(10);
    request.collection.capture.snap_length = 100;
    let report = client.identify_os(request, Collector::default()).unwrap();
    assert_eq!(report.stats.packets_attempted, 2);
    assert_eq!(
        steps
            .take()
            .iter()
            .filter(|step| matches!(step, crate::common::Step::Neighbor(_)))
            .count(),
        1
    );
}

#[test]
fn silent_layer2_preparation_preserves_the_operation_deadline_error() {
    let io = WaitingSilence(crate::common::RecordingTransmit::silent(
        crate::common::Steps::default(),
    ));
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        providers(
            crate::common::discovery::Routes {
                layer2: true,
                routed: false,
            },
            io,
        ),
    );
    let mut request = Request::new(
        Target::Address("192.0.2.2".parse().unwrap()),
        80,
        81,
        os::builtin_corpus().unwrap(),
    );
    request.route.link_mode = Mode::Layer2;
    request.timeout = Duration::from_secs(1);
    request.limits.max_duration = Duration::from_millis(100);
    let result = client.identify_os(request, Collector::default());
    assert!(matches!(result, Err(os::Error::Deadline(_))), "{result:?}");
}

#[derive(Clone)]
struct WaitingSilence(crate::common::RecordingTransmit);
struct SilentCapture(packetcraftr_netio::capture::Metadata);

impl packetcraftr_netio::transmit::Provider for WaitingSilence {
    fn send(
        &self,
        frame: packetcraftr_netio::transmit::Outbound<'_>,
    ) -> Result<packetcraftr_netio::transmit::Report, packetcraftr_netio::Error> {
        packetcraftr_netio::transmit::Provider::send(&self.0, frame)
    }
}

impl packetcraftr_netio::capture::Provider for WaitingSilence {
    type Capture = SilentCapture;
    fn arm_capture(
        &self,
        request: &packetcraftr_netio::capture::Request,
        _: &packetcraftr_core::budget::Deadline,
    ) -> Result<SilentCapture, packetcraftr_netio::Error> {
        Ok(SilentCapture(packetcraftr_netio::capture::Metadata {
            interface: request.interface.clone(),
            link_type: packetcraftr_core::frame::LinkType::ETHERNET,
            snap_length: request.limits.snap_length,
            native: Default::default(),
        }))
    }
}

impl packetcraftr_netio::capture::Session for SilentCapture {
    fn metadata(&self) -> &packetcraftr_netio::capture::Metadata {
        &self.0
    }
    fn wait_ready(
        &mut self,
        _: &packetcraftr_core::budget::Deadline,
    ) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<Option<packetcraftr_netio::capture::Captured>, packetcraftr_netio::Error> {
        // Unlike the immediate-empty fixture, model a genuinely silent capture
        // that waits until its caller's bounded response window ends.
        std::thread::sleep(deadline.live_remaining().unwrap_or_default());
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }
    fn stats(&self) -> packetcraftr_netio::capture::Stats {
        Default::default()
    }
}
