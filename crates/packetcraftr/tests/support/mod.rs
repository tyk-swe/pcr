// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::convert::Infallible;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use packetcraftr::core::frame::LinkType;
use packetcraftr::netio::interface::Id as InterfaceId;
use packetcraftr::netio::link::{Capability as LinkCapability, MacAddress};
use packetcraftr::netio::route::{Decision, Provider, Scope, SelectionReason};
use packetcraftr::netio::{Error as LiveIoError, capture, neighbor, transmit};
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
        }))
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

/// A writer the test can still read after handing it to an encoder.
#[derive(Clone, Default)]
pub(crate) struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl SharedWriter {
    pub(crate) fn records(&self) -> Vec<Value> {
        std::str::from_utf8(&self.0.lock().expect("shared writer lock"))
            .expect("encoded output must be UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("each record must be JSON"))
            .collect()
    }
}

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("shared writer lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The published output schema, parsed once per test binary.
pub(crate) fn output_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.output.v1.schema.json"
        ))
        .expect("published output schema must be JSON")
    })
}

/// A compiled validator for the published output schema.
pub(crate) fn output_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(output_schema()).expect("published output schema must compile")
    })
}

/// A compiled validator for the published packet-document schema.
pub(crate) fn packet_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.packet.v1.schema.json"
        ))
        .expect("published packet schema must be JSON");
        jsonschema::validator_for(&schema).expect("published packet schema must compile")
    })
}
