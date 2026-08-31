// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Protocol-aware DNS response classification, and the attempt evidence each
//! classification produces.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::protocol::BuiltinProtocol;
use packetcraftr_core::protocol::application::Dns;
use packetcraftr_core::{
    Packet, decode::DecodedPacket, diagnostic::Diagnostic, layer::Raw, registry::Registry,
};

use crate::evidence::{Budget, DiagnosticLog};
use crate::probe::evidence::{ResponseCandidate, retain_evidence};
use crate::probe::{self, Transport as ProbeTransport};

use super::EVIDENCE_DIAGNOSTICS;
use super::error::Error;
use super::model::{
    AttemptEvidence, Limits, MessageLimits, Outcome, Probe, Transport, ValidatedResponse,
};
use super::wire::{decode_response, decode_tcp_frame};

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
pub enum ResponseClassification {
    Response(ValidatedResponse),
    Unrelated { reason: String },
    DecodeFailure { reason: String },
    NetworkFailure { reason: String },
}

impl ResponseClassification {
    /// The attempt outcome this classification records.
    pub(crate) const fn outcome(&self) -> Outcome {
        match self {
            Self::Response(response) if response.metadata.truncated => Outcome::Truncated,
            Self::Response(_) => Outcome::Response,
            Self::NetworkFailure { .. } => Outcome::NetworkFailure,
            Self::DecodeFailure { .. } => Outcome::DecodeFailure,
            Self::Unrelated { .. } => Outcome::Unrelated,
        }
    }

    /// Precedence when several correlated frames arrive for one attempt; the
    /// same table [`Outcome::retry_rank`] applies across attempts.
    pub(crate) const fn rank(&self) -> u8 {
        self.outcome().retry_rank()
    }
}

pub fn classify_response(
    registry: &Registry,
    probe: &Probe,
    sent: &Packet,
    response: &DecodedPacket,
    limits: MessageLimits,
) -> Option<ResponseClassification> {
    if let Some(observation) = probe::observe(registry, ProbeTransport::Udp, sent, response)
        && observation.correlation.is_network_failure()
    {
        return Some(ResponseClassification::NetworkFailure {
            reason: observation.reason.to_owned(),
        });
    }
    if direct_udp_match(registry, sent, &response.packet) {
        if response
            .diagnostics
            .iter()
            .any(Diagnostic::is_checksum_failure)
        {
            return Some(ResponseClassification::DecodeFailure {
                reason: "correlated UDP response has an invalid checksum diagnostic".to_owned(),
            });
        }
        let Some(payload) = dns_payload(&response.packet) else {
            return Some(ResponseClassification::DecodeFailure {
                reason: "correlated UDP response has no complete DNS payload".to_owned(),
            });
        };
        return Some(
            match decode_response(
                &payload,
                &probe.query_name,
                probe.query_type,
                probe.transaction_id,
                limits,
            ) {
                Ok(validated) => ResponseClassification::Response(validated),
                Err(error) if error.is_unrelated() => ResponseClassification::Unrelated {
                    reason: error.to_string(),
                },
                Err(error) => ResponseClassification::DecodeFailure {
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
            .is_some_and(|matcher| matcher.matches(request, response).is_some())
}

pub(crate) fn dns_payload(packet: &Packet) -> Option<Bytes> {
    let udp_index = packet
        .iter()
        .position(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Udp))?;
    let udp = packet.layer(udp_index)?;
    let source_port = udp.field("source_port")?.as_u64()?;
    let destination_port = udp.field("destination_port")?.as_u64()?;
    let port_53 = source_port == 53 || destination_port == 53;
    let payload = packet.layer(udp_index.checked_add(1)?)?;
    match BuiltinProtocol::of(payload) {
        Some(BuiltinProtocol::Dns) if port_53 => payload
            .as_any()
            .downcast_ref::<Dns>()
            .map(|dns| dns.wire().clone()),
        Some(BuiltinProtocol::Malformed) if port_53 => payload
            .as_any()
            .downcast_ref::<packetcraftr_core::layer::Malformed>()
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

/// One classified attempt: either an accepted response, or the failure the
/// attempt is reported as.
///
/// The two shapes are separate because only an acceptance carries a validated
/// response; a 4-tuple could express a timeout that somehow also produced one.
#[derive(Debug)]
enum AttemptClassification {
    Accepted {
        /// The server set the truncation flag, so records were not accepted.
        truncated: bool,
        response_code: u16,
        reason: String,
        response: ValidatedResponse,
    },
    Failed {
        status: Outcome,
        reason: String,
    },
}

/// One classified attempt together with the response it accepted, if any.
pub(super) struct ClassifiedAttempt {
    pub(super) evidence: AttemptEvidence,
    pub(super) response: Option<ValidatedResponse>,
}

fn classify_attempt(classification: ResponseClassification) -> AttemptClassification {
    match classification {
        ResponseClassification::Response(response) => {
            let truncated = response.metadata.truncated;
            let reason = if truncated {
                "validated DNS response set the truncation flag; partial records were not accepted"
                    .to_owned()
            } else {
                format!(
                    "validated DNS response with code {}",
                    response.response_code_name()
                )
            };
            AttemptClassification::Accepted {
                truncated,
                response_code: response.metadata.response_code,
                reason,
                response,
            }
        }
        ResponseClassification::NetworkFailure { reason } => AttemptClassification::Failed {
            status: Outcome::NetworkFailure,
            reason,
        },
        ResponseClassification::DecodeFailure { reason } => AttemptClassification::Failed {
            status: Outcome::DecodeFailure,
            reason,
        },
        ResponseClassification::Unrelated { reason } => AttemptClassification::Failed {
            status: Outcome::Unrelated,
            reason,
        },
    }
}

/// Turns the best correlated UDP response into attempt evidence, retaining the
/// exact frame only while the operation's evidence budget allows it.
pub(super) fn candidate_evidence(
    probe: &Probe,
    sent_at: SystemTime,
    candidate: ResponseCandidate<'_, ResponseClassification>,
    limits: Limits,
    budget: &mut Budget,
    diagnostics: &mut DiagnosticLog,
) -> ClassifiedAttempt {
    let received_at = crate::live_timestamp(&candidate.decoded.frame);
    let response_frame = retain_evidence(
        budget,
        &candidate.decoded.frame,
        EVIDENCE_DIAGNOSTICS,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        diagnostics,
    )
    .then(|| candidate.decoded.frame.clone());
    let (status, response_code, reason, response) = match classify_attempt(candidate.observation) {
        AttemptClassification::Accepted {
            truncated,
            response_code,
            reason,
            response,
        } => (
            if truncated {
                Outcome::Truncated
            } else {
                Outcome::Response
            },
            Some(response_code),
            reason,
            Some(response),
        ),
        AttemptClassification::Failed { status, reason } => (status, None, reason, None),
    };
    ClassifiedAttempt {
        evidence: AttemptEvidence {
            attempt: probe.attempt,
            transport: Transport::Udp,
            server_address: probe.server_address,
            source_port: Some(probe.source_port),
            status,
            sent_at: Some(sent_at),
            received_at: Some(received_at),
            latency: Some(candidate.latency),
            response: response_frame,
            response_code,
            reason,
        },
        response,
    }
}

pub(super) fn timeout_evidence(probe: &Probe, sent_at: SystemTime) -> ClassifiedAttempt {
    ClassifiedAttempt {
        evidence: AttemptEvidence {
            attempt: probe.attempt,
            transport: Transport::Udp,
            server_address: probe.server_address,
            source_port: Some(probe.source_port),
            status: Outcome::Timeout,
            sent_at: Some(sent_at),
            received_at: None,
            latency: None,
            response: None,
            response_code: None,
            reason: "no checksum-valid, tuple-correlated DNS response before the deadline"
                .to_owned(),
        },
        response: None,
    }
}

pub(super) fn tcp_timeout_evidence(probe: &Probe, reason: &'static str) -> ClassifiedAttempt {
    tcp_failure_evidence(probe, Outcome::Timeout, reason.to_owned())
}

pub(super) fn tcp_failure_evidence(
    probe: &Probe,
    status: Outcome,
    reason: String,
) -> ClassifiedAttempt {
    ClassifiedAttempt {
        evidence: AttemptEvidence {
            attempt: probe.attempt,
            transport: Transport::Tcp,
            server_address: probe.server_address,
            source_port: None,
            status,
            sent_at: None,
            received_at: None,
            latency: None,
            response: None,
            response_code: None,
            reason,
        },
        response: None,
    }
}

/// Validates one DNS-over-TCP receipt against the request it answers, then
/// classifies its message. TCP socket bytes are never represented as captured
/// frame evidence.
pub(super) fn classify_tcp_response(
    probe: &Probe,
    timeout: Duration,
    response: packetcraftr_netio::dns_tcp::Response,
    limits: MessageLimits,
) -> Result<ClassifiedAttempt, Error> {
    let expected_written = probe
        .query
        .len()
        .checked_add(2)
        .ok_or(Error::InvalidEvidence {
            attempt: probe.attempt,
            message: "TCP query length accounting overflowed".to_owned(),
        })?;
    if response.local_address.port() == 0
        || response.peer_address != SocketAddr::new(probe.server_address, probe.server_port)
        || response.bytes_written != expected_written
        || response.elapsed > timeout
        || response.latency > response.elapsed
    {
        return Err(Error::InvalidEvidence {
            attempt: probe.attempt,
            message: "TCP executor returned inconsistent endpoint, byte, or deadline evidence"
                .to_owned(),
        });
    }
    let (status, response_code, reason, validated) = match decode_tcp_frame(
        &response.frame,
        &probe.query_name,
        probe.query_type,
        probe.transaction_id,
        limits,
    ) {
        Ok(validated) => (
            Outcome::Response,
            Some(validated.metadata.response_code),
            format!(
                "validated DNS-over-TCP response with code {}",
                validated.response_code_name()
            ),
            Some(validated),
        ),
        Err(error) if error.is_unrelated() => (Outcome::Unrelated, None, error.to_string(), None),
        Err(error) => (Outcome::DecodeFailure, None, error.to_string(), None),
    };
    Ok(ClassifiedAttempt {
        evidence: AttemptEvidence {
            attempt: probe.attempt,
            transport: Transport::Tcp,
            server_address: probe.server_address,
            source_port: Some(response.local_address.port()),
            status,
            sent_at: Some(response.sent_at),
            received_at: Some(response.received_at),
            latency: Some(response.latency),
            response: None,
            response_code,
            reason,
        },
        response: validated,
    })
}
