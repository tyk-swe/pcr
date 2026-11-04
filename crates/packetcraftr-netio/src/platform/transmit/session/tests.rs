// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
};

use bytes::Bytes;
use packetcraftr_core::frame::LinkType;

use super::{Backend, Bounded, Preparation};
use crate::{
    Error,
    interface::Id as InterfaceId,
    link::{Capability, Mode},
    route::{Decision, Scope, SelectionReason},
    transmit::{Outbound, Provider, Report, Route},
};

fn decision() -> Decision {
    Decision {
        interface: InterfaceId {
            name: "test0".to_owned(),
            index: 1,
        },
        source_mac: None,
        selected_source: None,
        preferred_source: None,
        next_hop: None,
        selection_reason: SelectionReason::OnLink,
        destination_scope: Scope::Link,
        mtu: 1500,
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    }
}

fn route<'a>(decision: &'a Decision, mode: Mode) -> Route<'a> {
    Route {
        decision,
        mode,
        lookup_destination: None,
    }
}

#[derive(Default)]
struct Counts {
    opens: AtomicUsize,
    sends: AtomicUsize,
    fallbacks: AtomicUsize,
    drops: AtomicUsize,
    namespace: AtomicUsize,
    generation: AtomicUsize,
    fail_open: AtomicBool,
    partial_send: AtomicBool,
    pause: Option<Arc<(Barrier, Barrier)>>,
}

struct TestResource {
    counts: Arc<Counts>,
    generation: usize,
}

impl Drop for TestResource {
    fn drop(&mut self) {
        self.counts.drops.fetch_add(1, SeqCst);
    }
}

struct TestBackend(Arc<Counts>, usize);

impl TestBackend {
    fn new(counts: Arc<Counts>) -> Self {
        let namespace = counts.namespace.load(SeqCst);
        Self(counts, namespace)
    }
}

impl Backend for TestBackend {
    type Key = (InterfaceId, usize, Option<IpAddr>);
    type Packet<'a> = Outbound<'a>;
    type Resource = TestResource;

    fn prepare<'a>(
        &self,
        outbound: Outbound<'a>,
    ) -> Result<Preparation<Self::Key, Outbound<'a>>, Error> {
        if self.0.namespace.load(SeqCst) != self.1 {
            return Err(Error::Send {
                message: "network namespace changed".to_owned(),
                source: None,
            });
        }
        if matches!(outbound, Outbound::Layer3(_)) {
            return Ok(Preparation::Fallback);
        }
        let route = outbound.route();
        Ok(Preparation::Reusable {
            key: (
                route.decision.interface.clone(),
                self.0.namespace.load(SeqCst),
                route.lookup_destination,
            ),
            packet: outbound,
        })
    }

    fn open(&self, _: &Outbound<'_>) -> Result<Option<Self::Resource>, Error> {
        self.0.opens.fetch_add(1, SeqCst);
        if self.0.fail_open.load(SeqCst) {
            return Err(Error::Send {
                message: "open failed".to_owned(),
                source: None,
            });
        }
        Ok(Some(TestResource {
            counts: self.0.clone(),
            generation: self.0.generation.load(SeqCst),
        }))
    }

    fn send(&self, resource: &mut Self::Resource, outbound: Outbound<'_>) -> Result<Report, Error> {
        self.0.sends.fetch_add(1, SeqCst);
        if let Some(pause) = &self.0.pause {
            pause.0.wait();
            pause.1.wait();
        }
        if resource.generation != self.0.generation.load(SeqCst) {
            return Err(Error::Send {
                message: "device removed".to_owned(),
                source: None,
            });
        }
        if self.0.partial_send.load(SeqCst) {
            return Err(Error::PartialSend {
                expected: outbound.bytes().len(),
                actual: 2,
            });
        }
        Ok(Report::committed(
            outbound.bytes().len(),
            outbound.bytes().clone(),
        ))
    }

    fn fallback(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        self.0.fallbacks.fetch_add(1, SeqCst);
        Ok(Report::committed(
            outbound.bytes().len(),
            outbound.bytes().clone(),
        ))
    }
}

#[test]
fn operation_session_reuses_one_resource_and_stops_after_device_loss() {
    let counts = Arc::new(Counts::default());
    let session = Bounded::new(TestBackend::new(counts.clone()));
    let decision = decision();
    let bytes = Bytes::from_static(b"packet bytes");
    let original = Outbound::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
    for _ in 0..8 {
        session
            .send(original)
            .unwrap()
            .validate_exact(&bytes)
            .unwrap();
    }
    assert_eq!(counts.opens.load(SeqCst), 1);
    assert_eq!(counts.sends.load(SeqCst), 8);

    let mut other = decision.clone();
    other.interface.index += 1;
    let other_interface = Outbound::try_new(&bytes, route(&other, Mode::Layer2)).unwrap();
    session
        .send(other_interface)
        .unwrap()
        .validate_exact(&bytes)
        .unwrap();
    counts.namespace.store(1, SeqCst);
    assert!(session.send(original).is_err());
    let layer3 = Outbound::try_new(&bytes, route(&decision, Mode::Layer3)).unwrap();
    assert!(session.send(layer3).is_err());
    counts.namespace.store(0, SeqCst);
    session
        .send(layer3)
        .unwrap()
        .validate_exact(&bytes)
        .unwrap();
    for destination in ["192.0.2.1", "2001:db8::1"] {
        let mut other_family = route(&decision, Mode::Layer2);
        other_family.lookup_destination = Some(destination.parse().unwrap());
        let outbound = Outbound::try_new(&bytes, other_family).unwrap();
        session
            .send(outbound)
            .unwrap()
            .validate_exact(&bytes)
            .unwrap();
    }
    assert_eq!(counts.fallbacks.load(SeqCst), 4);
    assert_eq!(counts.opens.load(SeqCst), 1);

    counts.generation.store(1, SeqCst);
    assert!(session.send(original).is_err());
    assert_eq!(counts.drops.load(SeqCst), 1);
    assert!(session.send(original).is_err());
    assert_eq!(counts.sends.load(SeqCst), 9);
    session
        .send(other_interface)
        .unwrap()
        .validate_exact(&bytes)
        .unwrap();
    assert_eq!(counts.fallbacks.load(SeqCst), 5);
    counts.generation.store(0, SeqCst);
    assert!(session.send(original).is_err());
    assert_eq!(counts.opens.load(SeqCst), 1);
    assert_eq!(counts.sends.load(SeqCst), 9);
    drop(session);
    assert_eq!(counts.drops.load(SeqCst), 1);
}

#[test]
fn failed_session_initialization_does_not_leave_a_resource() {
    let counts = Arc::new(Counts::default());
    counts.fail_open.store(true, SeqCst);
    let session = Bounded::new(TestBackend::new(counts.clone()));
    let decision = decision();
    let bytes = Bytes::from_static(b"packet");
    let outbound = Outbound::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
    assert!(session.send(outbound).is_err());
    assert_eq!(counts.sends.load(SeqCst), 0);
    counts.fail_open.store(false, SeqCst);
    session.send(outbound).unwrap();
    drop(session);
    assert_eq!(counts.opens.load(SeqCst), 2);
    assert_eq!(counts.drops.load(SeqCst), 1);
}

#[test]
fn session_preserves_partial_send_evidence_without_retrying() {
    use packetcraftr_core::error::{Classified, Code};
    let counts = Arc::new(Counts::default());
    counts.partial_send.store(true, SeqCst);
    let session = Bounded::new(TestBackend::new(counts.clone()));
    let decision = decision();
    let bytes = Bytes::from_static(b"packet");
    let outbound = Outbound::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
    for _ in 0..2 {
        let error = session.send(outbound).unwrap_err();
        assert!(matches!(
            error,
            Error::PartialSend {
                expected: 6,
                actual: 2
            }
        ));
        assert_eq!(error.classification().code, Code::IoPartialSend);
    }
    assert_eq!(counts.sends.load(SeqCst), 1);
    assert_eq!(counts.drops.load(SeqCst), 1);
}

#[test]
fn session_rejects_concurrent_sends_without_opening_another_resource() {
    let barriers = Arc::new((Barrier::new(2), Barrier::new(2)));
    let counts = Arc::new(Counts {
        pause: Some(barriers.clone()),
        ..Counts::default()
    });
    let session = Bounded::new(TestBackend::new(counts.clone()));
    let decision = decision();
    let bytes = Bytes::from_static(b"packet");
    let outbound = Outbound::try_new(&bytes, route(&decision, Mode::Layer2)).unwrap();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| session.send(outbound));
        barriers.0.wait();
        assert!(session.send(outbound).is_err());
        barriers.1.wait();
        first.join().unwrap().unwrap();
    });
    assert_eq!(counts.opens.load(SeqCst), 1);
    assert_eq!(counts.sends.load(SeqCst), 1);
}
