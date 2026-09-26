// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::Error as LiveIoError;
use packetcraftr_netio::capture;
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Capability as LinkCapability;
use packetcraftr_netio::route::Decision;
use packetcraftr_netio::route::Provider;
use packetcraftr_netio::route::Scope;
use packetcraftr_netio::route::SelectionReason;
use packetcraftr_netio::transmit;
use serde_json::Value;

/// The MAC address of the one interface [`FixedRoutes`] selects.
pub(crate) const INTERFACE_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
/// The source address [`FixedRoutes`] selects; packets sourced from it pass
/// the source-ownership check and fail only for the reason under test.
pub(crate) const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

/// A route provider that puts every destination on-link over one dual
/// capability Ethernet interface.
pub(crate) struct FixedRoutes;

impl Provider for FixedRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
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
pub(crate) struct NeverTransmit;

impl transmit::Provider for NeverTransmit {
    fn send(&self, _frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        unreachable!("a refused wire must not reach transmission")
    }
}

impl capture::Provider for NeverTransmit {
    type Capture = IdleCapture;

    fn arm_capture(&self, request: &capture::Request) -> Result<Self::Capture, LiveIoError> {
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

    fn arm_capture(&self, request: &capture::Request) -> Result<Self::Capture, LiveIoError> {
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
fn arp_reply(request: &[u8]) -> Option<(Ipv4Addr, Vec<u8>)> {
    const ARP_REQUEST: [u8; 10] = [0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1];
    if request.len() < 42 || request[12..22] != ARP_REQUEST {
        return None;
    }
    let requester_mac = &request[22..28];
    let requester_ip = &request[28..32];
    let target_ip = &request[38..42];
    let mut reply = Vec::with_capacity(60);
    reply.extend_from_slice(requester_mac);
    reply.extend_from_slice(&NEIGHBOR_MAC.0);
    reply.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 2]);
    reply.extend_from_slice(&NEIGHBOR_MAC.0);
    reply.extend_from_slice(target_ip);
    reply.extend_from_slice(requester_mac);
    reply.extend_from_slice(requester_ip);
    reply.resize(60, 0);
    let target = Ipv4Addr::new(target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    Some((target, reply))
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

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        Ok(self.replies.lock().expect("reply queue lock").pop_front())
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

/// A capture session that is ready at once and never yields a frame.
pub(crate) struct IdleCapture(capture::Metadata);

impl capture::Session for IdleCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.0
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
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
