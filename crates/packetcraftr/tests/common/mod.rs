// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]

pub(crate) mod clock;
pub(crate) mod dns;
pub(crate) mod responder;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use packetcraftr::ProviderSet;
use packetcraftr::target::{Hostname, Resolver};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::build::{self, Builder};
use packetcraftr_core::codec::Context;
use packetcraftr_core::decode::{self, Dissector};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Padding;
use packetcraftr_core::packet::{MacAddress, Packet};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::{Arp, Ethernet};
use packetcraftr_netio::Error as LiveIoError;
use packetcraftr_netio::capture;
use packetcraftr_netio::interface::{self, Id as InterfaceId};
use packetcraftr_netio::link::Capability as LinkCapability;
use packetcraftr_netio::route::Decision;
use packetcraftr_netio::route::Provider;
use packetcraftr_netio::route::Scope;
use packetcraftr_netio::route::SelectionReason;
use packetcraftr_netio::tcp;
use packetcraftr_netio::transmit;

pub(crate) const INTERFACE_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
pub(crate) const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

pub(crate) fn live() -> Deadline {
    Deadline::new(Duration::from_secs(5))
}

pub(crate) type FakeProviders<R, I> =
    ProviderSet<R, Interfaces, I, I, ScriptedTcp, ScriptedResolver>;

pub(crate) fn providers<R, I: Clone>(route: R, io: I) -> FakeProviders<R, I> {
    ProviderSet {
        route,
        interface: Interfaces::default(),
        capture: io.clone(),
        transmit: io,
        tcp: ScriptedTcp::default(),
        resolver: ScriptedResolver::default(),
    }
}

pub(crate) fn fixture_interface() -> interface::Info {
    interface::Info {
        id: InterfaceId {
            name: "fixture0".to_owned(),
            index: 1,
        },
        description: None,
        mac_address: Some(INTERFACE_MAC),
        addresses: Vec::new(),
        flags: interface::Flags::default(),
        mtu: Some(1_500),
        capability: LinkCapability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    }
}

#[derive(Clone)]
pub(crate) struct Interfaces {
    pub(crate) list: Vec<interface::Info>,
    pub(crate) steps: Steps,
}

impl Default for Interfaces {
    fn default() -> Self {
        Self {
            list: vec![fixture_interface()],
            steps: Steps::default(),
        }
    }
}

impl interface::Provider for Interfaces {
    fn interfaces(&self, _deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        self.steps.push(Step::Interfaces);
        Ok(self.list.clone())
    }
}

#[derive(Clone, Default)]
pub(crate) struct ScriptedTcp {
    pub(crate) steps: Steps,
}

impl tcp::Provider for ScriptedTcp {
    type Stream = tcp::SystemStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        self.steps.push(Step::Connect(endpoint));
        Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "fixture refusal").into())
    }
}

#[derive(Clone, Default)]
pub(crate) struct ScriptedResolver {
    pub(crate) steps: Steps,
}

impl Resolver for ScriptedResolver {
    fn resolve(
        &self,
        hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
        self.steps.push(Step::Resolve(hostname.to_string()));
        Ok(Vec::new())
    }
}

#[derive(Clone, Default)]
pub(crate) struct RecordingRoutes(pub(crate) Steps);

impl Provider for RecordingRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        self.0.push(Step::Route(destination));
        FixedRoutes.lookup_with_preferences(destination, interface_hint, preferred_source, deadline)
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct FixedRoutes;

impl Provider for FixedRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        Ok(Decision {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 1,
            },
            source_mac: Some(INTERFACE_MAC),
            selected_source: Some(IpAddr::V4(SELECTED_SOURCE)),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Link,
            mtu: 1_500,
            capability: LinkCapability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        })
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct NeverTransmit;

impl transmit::Provider for NeverTransmit {
    fn send(&self, _frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        unreachable!("a refused wire must not reach transmission")
    }
}

impl capture::Provider for NeverTransmit {
    type Capture = IdleCapture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, LiveIoError> {
        Ok(IdleCapture(capture::Metadata {
            interface: request.interface.clone(),
            link_type: LinkType::ETHERNET,
            snap_length: request.limits.snap_length,
            native: Default::default(),
        }))
    }
}

pub(crate) const NEIGHBOR_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    Neighbor(IpAddr),
    Transmit(Vec<u8>),
    Published(usize),
    Route(IpAddr),
    Interfaces,
    Connect(SocketAddr),
    Resolve(String),
}

#[derive(Clone, Default)]
pub(crate) struct Steps(Arc<Mutex<Vec<Step>>>);

impl Steps {
    pub(crate) fn push(&self, step: Step) {
        self.0.lock().expect("steps lock").push(step);
    }

    pub(crate) fn take(&self) -> Vec<Step> {
        std::mem::take(&mut *self.0.lock().expect("steps lock"))
    }
}

type Replies = Arc<Mutex<VecDeque<capture::Captured>>>;

#[derive(Clone, Default)]
pub(crate) struct RecordingTransmit {
    steps: Steps,
    armed: Arc<AtomicUsize>,
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    replies: Arc<Mutex<Replies>>,
    untimed: bool,
    silent: bool,
}

impl RecordingTransmit {
    pub(crate) fn new(steps: Steps) -> Self {
        Self {
            steps,
            ..Self::default()
        }
    }

    /// Answers neighbor requests with replies whose capture carries no
    /// wall-clock time.
    pub(crate) fn untimed(steps: Steps) -> Self {
        Self {
            steps,
            untimed: true,
            ..Self::default()
        }
    }

    /// Records neighbor requests without answering them.
    pub(crate) fn silent(steps: Steps) -> Self {
        Self {
            steps,
            silent: true,
            ..Self::default()
        }
    }

    pub(crate) fn armed(&self) -> usize {
        self.armed.load(Ordering::SeqCst)
    }

    /// The most captures that were armed at once.
    pub(crate) fn peak_armed(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

impl transmit::Provider for RecordingTransmit {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        let bytes = frame.bytes();
        let report = transmit::Submission::start().complete(bytes.len(), bytes.clone());
        match arp_reply(bytes) {
            Some((target, _)) if self.silent => {
                self.steps.push(Step::Neighbor(IpAddr::V4(target)));
            }
            Some((target, reply)) => {
                self.steps.push(Step::Neighbor(IpAddr::V4(target)));
                let reply = if self.untimed {
                    Frame::without_timestamp(LinkType::ETHERNET, reply)
                } else {
                    Frame::new(SystemTime::now(), LinkType::ETHERNET, reply)
                }
                .expect("ARP reply fixture");
                let replies = self.replies.lock().expect("replies lock").clone();
                replies
                    .lock()
                    .expect("reply queue lock")
                    .push_back(capture::Captured::new(reply, Instant::now()));
            }
            None => self.steps.push(Step::Transmit(bytes.to_vec())),
        }
        Ok(report)
    }
}

impl capture::Provider for RecordingTransmit {
    type Capture = ReplyCapture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, LiveIoError> {
        self.armed.fetch_add(1, Ordering::SeqCst);
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(live, Ordering::SeqCst);
        let replies = Replies::default();
        *self.replies.lock().expect("replies lock") = Arc::clone(&replies);
        Ok(ReplyCapture {
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::ETHERNET,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
            replies,
            live: Arc::clone(&self.live),
        })
    }
}

fn arp_reply(request: &[u8]) -> Option<(Ipv4Addr, Bytes)> {
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH,
        LinkType::ETHERNET,
        Bytes::copy_from_slice(request),
    )
    .ok()?;
    let decoded = Dissector::new(builtin::registry())
        .decode(frame, decode::Options::default())
        .ok()?;
    decoded.packet.layer(0)?.downcast_ref::<Ethernet>()?;
    let arp = decoded.packet.layer(1)?.downcast_ref::<Arp>()?;
    if arp.operation != 1 {
        return None;
    }
    let mut reply = Packet::new();
    reply.push(Ethernet {
        destination: arp.sender_hardware,
        source: NEIGHBOR_MAC.0,
        ether_type: WireValue::Auto,
    });
    reply.push(Arp {
        operation: 2,
        sender_hardware: NEIGHBOR_MAC.0,
        sender_protocol: arp.target_protocol,
        target_hardware: arp.sender_hardware,
        target_protocol: arp.sender_protocol,
        ..Arp::default()
    });
    reply.push(Padding::new(vec![0_u8; 18]));
    let reply = Builder::new(builtin::registry())
        .build(reply, Context::default(), build::Options::default())
        .ok()?;
    Some((arp.target_protocol, reply.bytes))
}

pub(crate) struct ReplyCapture {
    metadata: capture::Metadata,
    replies: Replies,
    live: Arc<AtomicUsize>,
}

impl Drop for ReplyCapture {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl capture::Session for ReplyCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        Ok(self.replies.lock().expect("reply queue lock").pop_front())
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

pub(crate) struct IdleCapture(capture::Metadata);

impl capture::Session for IdleCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.0
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}
pub mod scanner_fixture;
