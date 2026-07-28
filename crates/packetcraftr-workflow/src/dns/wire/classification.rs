// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol-aware DNS response classification.

use super::super::{
    Bytes, DecodedPacket, DiagnosticSeverity, DnsLimits, DnsProbe, FieldValue, Packet,
    ProbeTransport, ProtocolRegistry, ValidatedDnsResponse, probe,
};
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

/// Pure, protocol-aware classification of one decoded frame against an exact
/// DNS probe. `None` means the frame has no structural relationship to the
/// request. A reverse-tuple frame with invalid integrity remains typed decode
/// failure evidence, but can never become an accepted DNS response.
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
    registry: &ProtocolRegistry,
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
        let Some(payload) = raw_payload(&response.packet) else {
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

fn direct_udp_match(registry: &ProtocolRegistry, request: &Packet, response: &Packet) -> bool {
    if !response
        .iter()
        .any(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Udp))
    {
        return false;
    }
    let Some(udp) = request
        .iter()
        .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Udp))
    else {
        return false;
    };
    registry
        .matcher(udp.protocol_id().as_str())
        .is_some_and(|matcher| matcher.matches(request, response).matched)
}

pub(crate) fn raw_payload(packet: &Packet) -> Option<Bytes> {
    match packet
        .iter()
        .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Raw))?
        .field("bytes")?
    {
        FieldValue::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}
