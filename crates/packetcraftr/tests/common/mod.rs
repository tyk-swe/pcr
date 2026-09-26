// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime};

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
use serde_json::Value;

/// The MAC address of the one interface [`FixedRoutes`] selects.
pub(crate) const INTERFACE_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
/// The source address [`FixedRoutes`] selects; packets sourced from it pass
/// the source-ownership check and fail only for the reason under test.
pub(crate) const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

/// The fake provider bundle: the given route provider and one value serving
/// transmit and capture, with the fixture interface list, scripted TCP, and a
/// scripted resolver.
pub(crate) type FakeProviders<R, I> =
    ProviderSet<R, Interfaces, I, I, ScriptedTcp, ScriptedResolver>;

/// Composes [`FakeProviders`] from `route` and `io`, which transmits and
/// captures, with the default fixture interface list, refusing TCP, and a
/// resolver that answers nothing.
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

/// The one interface [`FixedRoutes`] selects, as an interface provider
/// enumerates it.
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

/// An interface provider answering a fixed list, [`fixture_interface`] by
/// default, recording [`Step::Interfaces`] for each enumeration.
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

/// A TCP provider that records [`Step::Connect`] for each attempt and then
/// refuses it, or with `loopback` set connects through the system provider,
/// which it allows only for loopback endpoints.
#[derive(Clone, Default)]
pub(crate) struct ScriptedTcp {
    pub(crate) loopback: bool,
    pub(crate) steps: Steps,
}

impl tcp::Provider for ScriptedTcp {
    type Stream = tcp::SystemStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        self.steps.push(Step::Connect(endpoint));
        if self.loopback {
            assert!(
                endpoint.ip().is_loopback(),
                "fixtures connect only to loopback"
            );
            return tcp::SystemProvider.connect(endpoint, deadline);
        }
        Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "fixture refusal").into())
    }
}

/// A resolver answering every hostname with `addresses`, recording
/// [`Step::Resolve`] for each call.
#[derive(Clone, Default)]
pub(crate) struct ScriptedResolver {
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) steps: Steps,
}

impl Resolver for ScriptedResolver {
    fn resolve(
        &self,
        hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
        self.steps.push(Step::Resolve(hostname.to_string()));
        Ok(self.addresses.clone())
    }
}

/// [`FixedRoutes`] that records [`Step::Route`] for each lookup.
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

/// A route provider that puts every destination on-link over one dual
/// capability Ethernet interface.
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

/// I/O for workflows that must fail before transmission: capture is armed
/// before routes are materialized, so it exists but never observes anything.
/// Neighbor discovery transmits, so it never runs over this I/O either.
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

/// The MAC address [`RecordingTransmit`] answers every ARP request with.
pub(crate) const NEIGHBOR_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);

/// One observable step recorded by the recording fakes, in the order it
/// happened. Tests may add their own [`Step::Published`] entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// An ARP request for this target was handed to the transmitter.
    Neighbor(IpAddr),
    /// These exact bytes were handed to the transmitter.
    Transmit(Vec<u8>),
    /// The workflow published the evidence of this confirmed send.
    Published(usize),
    /// The route provider was asked for a route to this destination.
    Route(IpAddr),
    /// The interface provider enumerated interfaces.
    Interfaces,
    /// A TCP connection to this endpoint was attempted.
    Connect(SocketAddr),
    /// This hostname was resolved.
    Resolve(String),
}

/// A shared, ordered record of provider calls.
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

/// I/O that records every frame it is handed and confirms it in full.
///
/// It answers each ARP request it transmits with [`NEIGHBOR_MAC`], recorded as
/// [`Step::Neighbor`], through the capture session armed last (the one neighbor
/// discovery armed for that request). Other captures never observe anything.
#[derive(Clone, Default)]
pub(crate) struct RecordingTransmit {
    steps: Steps,
    armed: Arc<AtomicUsize>,
    replies: Arc<Mutex<Replies>>,
}

impl RecordingTransmit {
    pub(crate) fn new(steps: Steps) -> Self {
        Self {
            steps,
            ..Self::default()
        }
    }

    /// How many capture sessions have been armed.
    pub(crate) fn armed(&self) -> usize {
        self.armed.load(Ordering::SeqCst)
    }
}

impl transmit::Provider for RecordingTransmit {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        let bytes = frame.bytes();
        let report = transmit::Submission::start().complete(bytes.len(), bytes.clone());
        match arp_reply(bytes) {
            Some((target, reply)) => {
                self.steps.push(Step::Neighbor(IpAddr::V4(target)));
                let reply = Frame::new(SystemTime::now(), LinkType::ETHERNET, reply)
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
        })
    }
}

/// The target of an untagged Ethernet ARP request, and the reply that
/// resolves it to [`NEIGHBOR_MAC`].
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

/// A capture session that is ready at once and yields the replies queued
/// for it.
pub(crate) struct ReplyCapture {
    metadata: capture::Metadata,
    replies: Replies,
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

/// A capture session that is ready at once and never yields a frame.
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

/// A compiled validator for the published packet-document schema.
pub(crate) fn packet_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.packet.v2.schema.json"
        ))
        .expect("published packet schema must be JSON");
        jsonschema::validator_for(&schema).expect("published packet schema must compile")
    })
}
