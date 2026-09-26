// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::Error as LiveIoError;
use packetcraftr_netio::capture;
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Capability as LinkCapability;
use packetcraftr_netio::neighbor;
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

/// A resolver for workflows that must fail before neighbor discovery.
pub(crate) struct NeverNeighbors;

impl neighbor::Resolver for NeverNeighbors {
    fn resolve(
        &self,
        _request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        unreachable!("a refused wire must not reach neighbor discovery")
    }
}

/// I/O for workflows that must fail before transmission: capture is armed
/// before routes are materialized, so it exists but never observes anything.
pub(crate) struct NeverTransmit;

impl transmit::Sender for NeverTransmit {
    fn send(&self, _frame: transmit::Frame<'_>) -> Result<transmit::Report, LiveIoError> {
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

/// The MAC address [`RecordingNeighbors`] resolves every target to.
pub(crate) const NEIGHBOR_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02]);

/// One observable step recorded by the recording fakes, in the order it
/// happened. Tests may add their own [`Step::Published`] entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// Neighbor discovery was requested for this target.
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

/// A resolver that records each discovery request and answers with
/// [`NEIGHBOR_MAC`].
pub(crate) struct RecordingNeighbors(pub(crate) Steps);

impl neighbor::Resolver for RecordingNeighbors {
    fn resolve(
        &self,
        request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        self.0.push(Step::Neighbor(request.target));
        Ok(neighbor::Resolution {
            mac_address: NEIGHBOR_MAC,
            attempts: 1,
            cache_hit: false,
            captured: Vec::new(),
            evidence_truncated: false,
            capture_statistics: capture::Statistics::default(),
        })
    }
}

/// I/O that records every frame it is handed and confirms it in full. Its
/// capture is armed but never observes anything.
pub(crate) struct RecordingTransmit(pub(crate) Steps);

impl transmit::Sender for RecordingTransmit {
    fn send(&self, frame: transmit::Frame<'_>) -> Result<transmit::Report, LiveIoError> {
        self.0.push(Step::Transmit(frame.bytes().to_vec()));
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

impl capture::Provider for RecordingTransmit {
    type Capture = IdleCapture;

    fn arm_capture(&self, request: &capture::Request) -> Result<Self::Capture, LiveIoError> {
        NeverTransmit.arm_capture(request)
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
