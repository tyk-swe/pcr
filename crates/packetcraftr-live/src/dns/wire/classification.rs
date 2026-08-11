// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol-aware DNS response classification.

use bytes::Bytes;
use packetcraftr_packet::protocol::application::Dns;
use packetcraftr_packet::{
    Packet,
    decode::Result as DecodedPacket,
    diagnostic::Severity as DiagnosticSeverity,
    layer::{Malformed as MalformedLayer, Raw},
    registry::Registry,
};

use crate::probe::{self, Transport as ProbeTransport};

use super::super::model::{DnsLimits, DnsProbe, ValidatedDnsResponse};
use super::decode::decode_dns_response;
use packetcraftr_packet::semantics::BuiltinProtocol;

pub const fn response_code_name(code: u16) -> &'static str {
    match code {
        0 => "no_error",
        1 => "format_error",
        2 => "server_failure",
        3 => "name_error",
        4 => "not_implemented",
        5 => "refused",
        6 => "yx_domain",
        7 => "yx_rrset",
        8 => "nx_rrset",
        9 => "not_authoritative",
        10 => "not_zone",
        16 => "bad_version",
        17 => "bad_key",
        18 => "bad_time",
        19 => "bad_mode",
        20 => "bad_name",
        21 => "bad_algorithm",
        22 => "bad_truncation",
        23 => "bad_cookie",
        _ => "unknown",
    }
}

/// Classifies a decoded frame against a DNS probe. Invalid correlated frames
/// are decode failures, never accepted responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsResponseClassification {
    Response(ValidatedDnsResponse),
    Unrelated { reason: String },
    DecodeFailure { reason: String },
    NetworkFailure { reason: String },
}

impl DnsResponseClassification {
    pub(crate) fn rank(&self) -> u8 {
        match self {
            Self::Response(_) => 4,
            Self::NetworkFailure { .. } => 3,
            Self::DecodeFailure { .. } => 2,
            Self::Unrelated { .. } => 1,
        }
    }
}

pub fn classify_dns_response(
    registry: &Registry,
    probe: &DnsProbe,
    sent: &Packet,
    response: &DecodedPacket,
    limits: DnsLimits,
) -> Option<DnsResponseClassification> {
    if let Some(observation) = probe::observe(registry, ProbeTransport::Udp, sent, response)
        && observation.correlation.is_network_failure()
    {
        return Some(DnsResponseClassification::NetworkFailure {
            reason: observation.reason.to_owned(),
        });
    }
    if direct_udp_match(registry, sent, &response.packet) {
        if response.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.contains("checksum") && diagnostic.severity != DiagnosticSeverity::Info
        }) {
            return Some(DnsResponseClassification::DecodeFailure {
                reason: "correlated UDP response has an invalid checksum diagnostic".to_owned(),
            });
        }
        let Some(payload) = dns_payload(&response.packet) else {
            return Some(DnsResponseClassification::DecodeFailure {
                reason: "correlated UDP response has no complete DNS payload".to_owned(),
            });
        };
        return Some(
            match decode_dns_response(
                &payload,
                &probe.query_name,
                probe.query_type,
                probe.transaction_id,
                limits,
            ) {
                Ok(validated) => DnsResponseClassification::Response(validated),
                Err(error) if error.is_unrelated() => DnsResponseClassification::Unrelated {
                    reason: error.to_string(),
                },
                Err(error) => DnsResponseClassification::DecodeFailure {
                    reason: error.to_string(),
                },
            },
        );
    }

    None
}

fn direct_udp_match(registry: &Registry, request: &Packet, response: &Packet) -> bool {
    response
        .iter()
        .any(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Udp))
        && request
            .iter()
            .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Udp))
            .and_then(|udp| registry.matcher(udp.protocol_id().as_str()))
            .is_some_and(|matcher| matcher.matches(request, response).matched)
}

pub(crate) fn dns_payload(packet: &Packet) -> Option<Bytes> {
    let udp_index = packet
        .iter()
        .position(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Udp))?;
    let udp = packet.layer(udp_index)?;
    let source_port = udp.field("source_port")?.as_u64()?;
    let destination_port = udp.field("destination_port")?.as_u64()?;
    let port_53 = source_port == 53 || destination_port == 53;
    let payload = packet.layer(udp_index + 1)?;
    match BuiltinProtocol::of(payload) {
        Some(BuiltinProtocol::Dns) if port_53 => payload
            .as_any()
            .downcast_ref::<Dns>()
            .map(|dns| dns.wire().clone()),
        Some(BuiltinProtocol::Malformed) if port_53 => payload
            .as_any()
            .downcast_ref::<MalformedLayer>()
            .filter(|layer| {
                layer
                    .intended_protocol
                    .as_ref()
                    .is_some_and(|protocol| protocol.as_str() == "dns")
            })
            .map(|layer| layer.bytes.clone()),
        Some(BuiltinProtocol::Raw) => payload
            .as_any()
            .downcast_ref::<Raw>()
            .map(|raw| raw.bytes.clone()),
        _ => None,
    }
}
