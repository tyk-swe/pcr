// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::{Packet, decode::Result as DecodedPacket, registry::Registry};

use crate::probe::Correlation;

use super::model::{ScanClassification, ScanTransport};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanResponseClassification {
    pub classification: ScanClassification,
    pub responder: IpAddr,
    pub reason: &'static str,
    pub(super) correlation: Correlation,
}

/// Classifies a valid correlated response; corrupt, unrelated, or inconsistent
/// responses return `None`.
pub fn classify_scan_response(
    registry: &Registry,
    transport: ScanTransport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<ScanResponseClassification> {
    let observation =
        crate::probe::observe(registry, transport.probe_transport(), request, response)?;
    let classification = match observation.correlation {
        Correlation::TcpReset | Correlation::PortUnreachable => ScanClassification::Closed,
        Correlation::TcpSynAck | Correlation::UdpReply | Correlation::IcmpReply => {
            ScanClassification::Open
        }
        Correlation::TcpOther => ScanClassification::Unknown,
        Correlation::TimeExceeded | Correlation::AdministrativelyProhibited => {
            ScanClassification::Filtered
        }
        Correlation::DestinationUnreachable => ScanClassification::Unreachable,
    };
    Some(ScanResponseClassification {
        classification,
        responder: observation.responder,
        reason: observation.reason,
        correlation: observation.correlation,
    })
}
