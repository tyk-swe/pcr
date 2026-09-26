// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::build::BuiltPacket;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::transmit::Report as TransmissionReport;

use crate::BoundaryError;
use crate::clock::Clock;
use crate::evidence::SentPacket;
use crate::policy::Authorizer;
use crate::policy::Operation;
use crate::probe::{Executor, Request};
use crate::target::Authorized;
use crate::target::Error as TargetError;
use crate::target::Hostname;
use crate::target::Resolver;
use crate::target::Target;

#[derive(Default)]
pub(crate) struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct RecordingClock {
    pub(crate) delays: Vec<Duration>,
    instant: Option<std::time::Instant>,
}

impl Clock for RecordingClock {
    type Error = Infallible;

    fn now(&mut self) -> std::time::Instant {
        *self.instant.get_or_insert_with(std::time::Instant::now)
    }

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.instant = self.now().checked_add(delay);
        self.delays.push(delay);
        Ok(())
    }
}

/// An authorizer that approves every operation and hands back fixed addresses.
pub(crate) struct AddressListAuthorizer {
    pub(crate) addresses: Vec<IpAddr>,
}

impl Authorizer for AddressListAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            addresses: self.addresses.clone(),
        })
    }

    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(
            matches!(operation, Operation::Budgeted(_)),
            "target workflows submit budget-only requests, got {operation:?}"
        );
        Ok(())
    }
}

/// A resolver that replays a queued script of answers and counts its calls.
pub(crate) struct ScriptedResolver {
    pub(crate) calls: Arc<AtomicUsize>,
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl ScriptedResolver {
    pub(crate) fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }
}

impl Resolver for ScriptedResolver {
    fn resolve(&self, _hostname: &Hostname, _limit: usize) -> Result<Vec<IpAddr>, TargetError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .expect("resolver lock")
            .pop_front()
            .expect("scripted resolver answer"))
    }
}

/// An executor that refuses every request and counts how often it was asked.
pub(crate) struct RejectingExecutor {
    pub(crate) calls: Arc<AtomicUsize>,
}

impl<Req: Request> Executor<Req> for RejectingExecutor {
    fn execute(&mut self, _request: &Req) -> Result<Req::Execution, BoundaryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(BoundaryError::new(
            "stop after authorization",
            Classification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    }
}

/// A trusted sent-packet record for `packet` on a fixed Layer 3 route.
pub(crate) fn sent_packet(packet: Packet) -> SentPacket {
    use packetcraftr_netio::transmit::Submission;

    let built = built_packet(packet);
    let report = Submission::start().complete(built.bytes.len(), built.bytes.clone());
    SentPacket::try_new(built, materialized_route(), report).expect("valid trusted sent fixture")
}

/// A trusted sent-packet record carrying the given transmission report.
pub(crate) fn sent_packet_with_report(packet: Packet, report: TransmissionReport) -> SentPacket {
    SentPacket::try_new(built_packet(packet), materialized_route(), report)
        .expect("valid trusted sent fixture")
}

fn built_packet(packet: Packet) -> BuiltPacket {
    use packetcraftr_core::build::{Builder, Options};
    use packetcraftr_core::codec::Context;

    Builder::new(packetcraftr_core::protocol::builtin::registry())
        .build(packet, Context::default(), Options::default())
        .expect("sent-packet fixture must build")
}

fn materialized_route() -> packetcraftr_netio::route::Materialized {
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_netio::{
        interface::Id as InterfaceId,
        link::{Capability, Mode},
        route::{Decision, Materialized, Plan},
    };

    Materialized {
        plan: Plan {
            decision: Decision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                source_mac: None,
                selected_source: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: packetcraftr_netio::route::SelectionReason::InterfaceOnly,
                destination_scope: packetcraftr_netio::route::Scope::Link,
                mtu: u32::MAX,
                capability: Capability::Layer3,
                link_type: LinkType::RAW,
            },
            mode: Mode::Layer3,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: None,
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    }
}
