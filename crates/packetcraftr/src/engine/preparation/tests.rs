// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{ProviderSet, policy::DestinationConstraint};
use bytes::Bytes;
use packetcraftr_core::{
    budget::Cancellation,
    frame::LinkType,
    layer::Raw,
    packet::MacAddress,
    protocol::{builtin, network::Ipv4, transport::Udp},
};
use packetcraftr_netio::{
    Error as LiveIoError, capture, interface,
    link::{Capability, Mode},
    route::{Decision, Provider as RouteProvider, Scope, SelectionReason},
    transmit,
};
use std::{
    convert::Infallible,
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Clone)]
struct Routes {
    decision: Arc<Mutex<Decision>>,
    calls: Arc<AtomicUsize>,
}
impl RouteProvider for Routes {
    type Error = Infallible;
    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Infallible> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.decision.lock().unwrap().clone())
    }
}

#[derive(Clone)]
struct Interfaces {
    id: Arc<Mutex<interface::Id>>,
    calls: Arc<AtomicUsize>,
}
impl interface::Provider for Interfaces {
    fn interfaces(&self, _: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(vec![interface::Info {
            id: self.id.lock().unwrap().clone(),
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: Default::default(),
            mtu: Some(9000),
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }])
    }
}

struct NoCapture;
struct NoCaptureSession;
impl capture::Provider for NoCapture {
    type Capture = NoCaptureSession;
    fn arm_capture(
        &self,
        _: &capture::Request,
        _: &Deadline,
    ) -> Result<NoCaptureSession, LiveIoError> {
        panic!("preparation must not arm capture")
    }
}
impl capture::Session for NoCaptureSession {
    fn metadata(&self) -> &capture::Metadata {
        panic!("capture must not exist")
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), LiveIoError> {
        panic!("capture must not exist")
    }
    fn next_captured_frame(
        &mut self,
        _: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        panic!("capture must not exist")
    }
    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        panic!("capture must not exist")
    }
    fn stats(&self) -> capture::Stats {
        Default::default()
    }
}

#[derive(Clone, Default)]
struct Transmit(Arc<Mutex<Vec<Bytes>>>);
impl transmit::Provider for Transmit {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        self.0.lock().unwrap().push(frame.bytes().clone());
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

type TestClient = Client<ProviderSet<Routes, Interfaces, NoCapture, Transmit>>;
fn fixture() -> (TestClient, Routes, Interfaces, Transmit) {
    let id = interface::Id {
        index: 1,
        name: "controlled0".to_owned(),
    };
    let routes = Routes {
        decision: Arc::new(Mutex::new(Decision {
            interface: id.clone(),
            source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
            selected_source: Some("10.0.0.2".parse().unwrap()),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Private,
            mtu: 9000,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        })),
        calls: Arc::default(),
    };
    let interfaces = Interfaces {
        id: Arc::new(Mutex::new(id)),
        calls: Arc::default(),
    };
    let tx = Transmit::default();
    let policy = Policy {
        allowed_destinations: vec![DestinationConstraint::Exact("10.0.0.1".parse().unwrap())],
        ..Policy::default()
    };
    let client = Client::new(
        builtin::registry(),
        policy,
        ProviderSet::packet(routes.clone(), interfaces.clone(), NoCapture, tx.clone()),
    );
    (client, routes, interfaces, tx)
}

pub(crate) fn client_for_plan() -> Client<impl crate::providers::PacketProviders> {
    fixture().0
}
fn options() -> Options {
    Options {
        plan: route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        ..Default::default()
    }
}
fn packet(bytes: usize) -> Packet {
    let mut packet = Packet::default();
    packet.push(Ipv4 {
        destination: "10.0.0.1".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 12345,
        destination_port: 9,
        ..Default::default()
    });
    packet.push(Raw::new(vec![7; bytes]));
    packet
}

#[test]
fn interrupted_neighbor_io_preserves_sent_request_statistics() {
    let (client, routes, _, _) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let options = Options {
        plan: route::Options {
            link_mode: Mode::Layer2,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut admission = client
        .admitting_in(&options, 1, &deadline, &operation)
        .unwrap();
    let packet = packet(1);
    let route = admission
        .route_on(&packet, "10.0.0.1".parse().unwrap(), None)
        .unwrap();
    let admitted = admission.admit_on(packet, &route).unwrap();
    let request = route::neighbor_request(&route.plan).unwrap();
    routes.decision.lock().unwrap().source_mac = None;
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let result = admission
        .discover()
        .stages
        .materialize_using(admitted, |_, _| {
            Err(crate::neighbor::Error::Io {
                interface: request.interface.name.clone().into_boxed_str(),
                target: request.target,
                operation: "receiving discovery response",
                spent: Some(Box::new(crate::neighbor::FailureEvidence {
                    attempts: 1,
                    captured: Box::default(),
                    evidence_truncated: false,
                })),
                source: LiveIoError::Cancelled(packetcraftr_core::budget::Cancelled),
            }
            .into())
        });
    let Err(error) = result else {
        panic!("interrupted neighbor discovery unexpectedly succeeded");
    };
    let Error::NeighborSpent(spent) = error else {
        panic!("expected sent-request evidence on the preparation failure");
    };
    assert_eq!(spent.stats.packets_attempted, 1);
    assert_eq!(spent.stats.packets_completed, 1);
    assert_eq!(
        spent.stats.bytes,
        crate::neighbor::request_frame(&request).unwrap().len() as u64
    );
    assert!(matches!(
        spent.error,
        Error::Plan(route::Error::Neighbor(_))
    ));
}

#[test]
fn multipath_source_change_is_rejected_before_capture_or_transmission() {
    let (client, routes, _, tx) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let options = options();
    let prepared = client
        .streaming_in(&options, 1, &operation)
        .unwrap()
        .prepare(packet(1))
        .unwrap();
    let mut pinned = Some(prepared.route().plan.clone());
    routes.decision.lock().unwrap().selected_source = Some("10.0.0.3".parse().unwrap());
    let result = client.exchange_packets(
        vec![packet(1)],
        &options,
        Duration::from_secs(1),
        crate::exchange::Collection::default(),
        &operation,
        &mut |_, _, _| false,
        &mut pinned,
    );
    assert!(matches!(
        result,
        Err(crate::exchange::Error::HeterogeneousRoute)
    ));
    assert!(tx.0.lock().unwrap().is_empty());
}

#[test]
fn route_name_accounting_uses_owned_capacities_and_counts_scoped_names() {
    let (client, _, interfaces, _) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let options = options();
    let mut admission = client
        .admitting_in(&options, 1, &deadline, &operation)
        .unwrap();
    let id = interfaces.id.lock().unwrap().clone();
    let mut route = admission
        .route_on(&packet(64), "10.0.0.1".parse().unwrap(), Some(&id))
        .unwrap();
    let mut name = String::with_capacity(8192);
    name.push_str(&id.name);
    route.plan.decision.interface.name = name;
    let mut scoped_name = String::with_capacity(4096);
    scoped_name.push_str(&id.name);
    route.scoped_interface.as_mut().unwrap().name = scoped_name;
    assert_eq!(
        route.retained_name_bytes(),
        route.plan.decision.interface.name.capacity()
            + route.scoped_interface.as_ref().unwrap().name.capacity()
    );
    assert!(route.retained_name_bytes() >= 12_288);
    assert_eq!(route.scoped_name_bytes(), id.name.len());
    let mut admitted = admission.admit_on(packet(64), &route).unwrap();
    admitted.plan.decision.interface.name.reserve(16_384);
    assert_eq!(
        admitted.retained_route_name_bytes(),
        admitted.plan.decision.interface.name.capacity()
    );
    assert!(admitted.retained_route_name_bytes() >= 16_384);
}

#[test]
fn stable_preview_avoids_second_build_but_refreshes_route_and_preserves_exact_bytes() {
    let (client, routes, _, tx) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let options = options();
    let mut results = Vec::new();
    for retain in [false, true] {
        work::take();
        let initial_calls = routes.calls.load(Ordering::Relaxed);
        let mut admission = client
            .admitting_in(&options, 1, &deadline, &operation)
            .unwrap();
        let declaration = packet(64);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = if retain {
            admission.admit_retained_on(declaration, &route)
        } else {
            admission.admit_on(declaration, &route)
        }
        .unwrap();
        let expected_bytes = admitted.preliminary_build.bytes.clone();
        let (cost, retained) = admitted.into_parts();
        let discovery = &admission;
        let prepared = match retained {
            Some(retained) => discovery.materialize_retained(retained, &route, cost),
            None => discovery.rebuild(packet(64), &route, cost),
        }
        .unwrap();
        assert_eq!(prepared.built.bytes, expected_bytes);
        let counts = work::take();
        assert_eq!(counts, if retain { (1, 1, 1) } else { (2, 2, 0) });
        assert_eq!(
            routes.calls.load(Ordering::Relaxed) - initial_calls,
            2,
            "final route lookup remains fresh"
        );
        results.push(
            prepared
                .transmit(&tx, || Ok::<(), Error>(()))
                .unwrap()
                .built()
                .bytes
                .clone(),
        );
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(tx.0.lock().unwrap().len(), 2);
}

#[test]
fn bounded_windows_measure_actual_builds_and_fresh_route_lookups() {
    for count in [4, 32] {
        for retain in [false, true] {
            let (client, routes, _, _) = fixture();
            let operation = Execution::new(&client, Duration::from_secs(10));
            let deadline = operation.deadline(&client, Duration::from_secs(10));
            let options = options();
            let mut admission = client
                .admitting_in(&options, count, &deadline, &operation)
                .unwrap();
            let route = admission
                .route_on(&packet(64), "10.0.0.1".parse().unwrap(), None)
                .unwrap();
            work::take();
            let mut window = Vec::new();
            for _ in 0..count {
                let admitted = if retain {
                    admission.admit_retained_on(packet(64), &route)
                } else {
                    admission.admit_on(packet(64), &route)
                }
                .unwrap();
                window.push(admitted.into_parts());
            }
            assert_eq!(admission.wire_bytes(), count * 92);
            let discovery = &admission;
            for (cost, retained) in window {
                let prepared = match retained {
                    Some(retained) => discovery.materialize_retained(retained, &route, cost),
                    None => discovery.rebuild(packet(64), &route, cost),
                }
                .unwrap();
                assert_eq!(prepared.built.bytes.len(), 92);
            }
            let measured = work::take();
            let count = count as usize;
            assert_eq!(
                measured,
                if retain {
                    (count, count, count)
                } else {
                    (2 * count, 2 * count, 0)
                }
            );
            assert_eq!(routes.calls.load(Ordering::Relaxed), count + 1);
            println!(
                "window={count} retain={retain} builds={} preparation_passes={} preview_reuses={} fresh_route_calls={}",
                measured.0,
                measured.1,
                measured.2,
                routes.calls.load(Ordering::Relaxed)
            );
        }
    }
}

#[test]
fn changed_final_declaration_is_authorized_before_fresh_provider_lookup() {
    let (client, routes, _, tx) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let options = options();
    let mut admission = client
        .admitting_in(&options, 1, &deadline, &operation)
        .unwrap();
    let declaration = packet(64);
    let route = admission
        .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
        .unwrap();
    let cost = admission
        .admit_on(declaration, &route)
        .unwrap()
        .into_parts()
        .0;
    let mut changed = packet(64);
    changed.get_mut::<Ipv4>().unwrap().destination = "10.0.0.9".parse().unwrap();
    let result = admission.rebuild(changed, &route, cost);
    assert!(matches!(
        result,
        Err(RebuildError::Preparation(Error::Policy(_)))
    ));
    assert_eq!(routes.calls.load(Ordering::Relaxed), 1);
    assert!(tx.0.lock().unwrap().is_empty());
}

#[test]
fn borrowed_materialization_keeps_one_cumulative_admission_budget() {
    let (mut client, routes, _, tx) = fixture();
    Arc::make_mut(&mut client.policy).max_bytes_per_operation = 200;
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let options = options();
    let mut admission = client
        .admitting_in(&options, 3, &deadline, &operation)
        .unwrap();
    let route = admission
        .route_on(&packet(64), "10.0.0.1".parse().unwrap(), None)
        .unwrap();

    let (first_cost, first_preview) = admission
        .admit_retained_on(packet(64), &route)
        .unwrap()
        .into_parts();
    assert_eq!(admission.wire_bytes(), 92);
    let first = admission
        .materialize_retained(first_preview.unwrap(), &route, first_cost)
        .unwrap();
    assert_eq!(
        admission.wire_bytes(),
        92,
        "materialization does not charge again"
    );
    first.transmit(&tx, || Ok::<(), Error>(())).unwrap();

    let second_cost = admission.admit_on(packet(64), &route).unwrap().into_cost();
    assert_eq!(admission.wire_bytes(), 184);
    let second = admission.rebuild(packet(64), &route, second_cost).unwrap();
    assert_eq!(admission.wire_bytes(), 184);
    second.transmit(&tx, || Ok::<(), Error>(())).unwrap();
    assert!(matches!(
        admission.admit_on(packet(64), &route),
        Err(Error::Policy(crate::policy::Error::ByteLimit { .. }))
    ));
    assert_eq!(
        admission.wire_bytes(),
        184,
        "refusal cannot fork or reset spending"
    );

    let mut other = client
        .admitting_in(&options, 1, &deadline, &operation)
        .unwrap();
    let (foreign_cost, foreign_preview) = other
        .admit_retained_on(packet(64), &route)
        .unwrap()
        .into_parts();
    let before = routes.calls.load(Ordering::Relaxed);
    assert!(matches!(
        admission.materialize_retained(foreign_preview.unwrap(), &route, foreign_cost),
        Err(RebuildError::Preparation(
            Error::PacketMaterialization { .. }
        ))
    ));
    assert_eq!(routes.calls.load(Ordering::Relaxed), before);
    assert_eq!(admission.wire_bytes(), 184);
    assert_eq!(tx.0.lock().unwrap().len(), 2);
}

#[test]
fn changed_source_rebuilds_and_changed_mtu_fails_before_discovery() {
    for (mode, shrink_mtu) in [
        (Mode::Layer3, false),
        (Mode::Layer3, true),
        (Mode::Layer2, true),
    ] {
        let (client, routes, _, tx) = fixture();
        let operation = Execution::new(&client, Duration::from_secs(10));
        let deadline = operation.deadline(&client, Duration::from_secs(10));
        let mut options = options();
        options.plan.link_mode = mode;
        let mut admission = client
            .admitting_in(&options, 1, &deadline, &operation)
            .unwrap();
        let declaration = packet(1024);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = admission.admit_retained_on(declaration, &route).unwrap();
        let (cost, retained) = admitted.into_parts();
        let discovery = &admission;
        work::take();
        let mut decision = routes.decision.lock().unwrap();
        if shrink_mtu {
            decision.mtu = 512;
        } else {
            decision.selected_source = Some("10.0.0.3".parse().unwrap());
        }
        drop(decision);
        let result = discovery.materialize_retained(retained.unwrap(), &route, cost);
        if shrink_mtu {
            assert!(matches!(
                result,
                Err(RebuildError::Preparation(Error::PacketExceedsMtu {
                    mtu: 512,
                    ..
                }))
            ));
        } else {
            assert_eq!(
                result.unwrap().built.packet.get::<Ipv4>().unwrap().source,
                "10.0.0.3".parse::<std::net::Ipv4Addr>().unwrap()
            );
        }
        assert_eq!(work::take(), (1, 1, 0));
        assert!(tx.0.lock().unwrap().is_empty());
    }
}

#[test]
fn interface_selectors_are_resolved_again_and_capture_identity_change_is_refused() {
    let (client, routes, interfaces, tx) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let mut options = options();
    options.plan.interface = Some(route::Interface::Name("controlled0".to_owned()));
    let mut admission = client
        .admitting_in(&options, 1, &deadline, &operation)
        .unwrap();
    let declaration = packet(64);
    let route = admission
        .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
        .unwrap();
    let admitted = admission.admit_retained_on(declaration, &route).unwrap();
    let (cost, retained) = admitted.into_parts();
    interfaces.id.lock().unwrap().index = 2;
    routes.decision.lock().unwrap().interface.index = 2;
    let result = admission.materialize_retained(retained.unwrap(), &route, cost);
    assert!(matches!(
        result,
        Err(RebuildError::Preparation(Error::Plan(
            route::Error::InterfaceMismatch {
                requested_index: 1,
                selected_index: 2,
                ..
            }
        )))
    ));
    assert_eq!(interfaces.calls.load(Ordering::Relaxed), 2);
    assert!(tx.0.lock().unwrap().is_empty());
}

#[test]
fn cancellation_and_other_admission_costs_cannot_enter_reuse() {
    for foreign_cost in [false, true] {
        let (client, routes, _, _) = fixture();
        let signal = Cancellation::default();
        let operation = Execution::new(&client, Duration::from_secs(10));
        let deadline = operation
            .deadline(&client, Duration::from_secs(10))
            .with_cancellation(Some(signal.clone()));
        let options = options();
        let mut admission = client
            .admitting_in(&options, 1, &deadline, &operation)
            .unwrap();
        let declaration = packet(64);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = admission.admit_retained_on(declaration, &route).unwrap();
        let (cost, retained) = admitted.into_parts();
        let discovery = if foreign_cost {
            client
                .admitting_in(&options, 1, &deadline, &operation)
                .unwrap()
        } else {
            signal.cancel();
            admission
        };
        let before = routes.calls.load(Ordering::Relaxed);
        let error = discovery
            .materialize_retained(retained.unwrap(), &route, cost)
            .err()
            .unwrap();
        assert!(
            matches!(
                error,
                RebuildError::Preparation(Error::PacketMaterialization { .. })
            ) == foreign_cost
        );
        assert!(matches!(error, RebuildError::Preparation(Error::Cancelled(_))) != foreign_cost);
        assert_eq!(routes.calls.load(Ordering::Relaxed), before);
    }
}

#[test]
fn changed_wire_length_and_cumulative_budget_are_refused_before_discovery() {
    for mode in [Mode::Layer2, Mode::Layer3] {
        let (mut client, routes, _, tx) = fixture();
        Arc::make_mut(&mut client.policy).max_bytes_per_operation = 150;
        let operation = Execution::new(&client, Duration::from_secs(10));
        let deadline = operation.deadline(&client, Duration::from_secs(10));
        let mut options = options();
        options.plan.link_mode = mode;
        let mut admission = client
            .admitting_in(&options, 2, &deadline, &operation)
            .unwrap();
        let declaration = packet(64);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = admission.admit_on(declaration, &route).unwrap();
        let admitted_bytes = if mode == Mode::Layer3 { 92 } else { 106 };
        assert_eq!(admission.wire_bytes(), admitted_bytes);
        assert!(matches!(
            admission.admit_on(packet(64), &route),
            Err(Error::Policy(crate::policy::Error::ByteLimit { .. }))
        ));
        assert_eq!(
            admission.wire_bytes(),
            admitted_bytes,
            "refused charge does not spend again"
        );
        let result = admission.rebuild(packet(65), &route, admitted.into_parts().0);
        assert!(matches!(
            result,
            Err(RebuildError::Changed { admitted }) if admitted == admitted_bytes as usize
        ));
        assert_eq!(routes.calls.load(Ordering::Relaxed), 2);
        assert!(tx.0.lock().unwrap().is_empty());
    }
}
