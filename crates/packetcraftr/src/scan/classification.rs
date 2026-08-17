// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::{Packet, decode::DecodedPacket, registry::Registry};

use crate::probe::Correlation;

use super::model::{Classification, Transport};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseClassification {
    pub classification: Classification,
    pub responder: IpAddr,
    pub reason: &'static str,
}

/// Classifies a valid correlated response; corrupt, unrelated, or inconsistent
/// responses return `None`.
pub fn classify_response(
    registry: &Registry,
    transport: Transport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<ResponseClassification> {
    let observation =
        crate::probe::observe(registry, transport.probe_transport(), request, response)?;
    let classification = match observation.correlation {
        Correlation::TcpReset | Correlation::PortUnreachable => Classification::Closed,
        Correlation::TcpSynAck | Correlation::UdpReply | Correlation::IcmpReply => {
            Classification::Open
        }
        Correlation::TcpOther => Classification::Unknown,
        Correlation::TimeExceeded | Correlation::AdministrativelyProhibited => {
            Classification::Filtered
        }
        Correlation::DestinationUnreachable => Classification::Unreachable,
    };
    Some(ResponseClassification {
        classification,
        responder: observation.responder,
        reason: observation.reason,
    })
}
