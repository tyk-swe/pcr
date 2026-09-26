// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::protocol::{BuiltinProtocol, transport_tuple_reversed};
use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, layer::Raw, packet::Packet, registry::Registry,
};

use crate::correlation::{self, Transport as ProbeTransport};
use crate::execution::evidence::{EvidenceState, ResponseCandidate};

use super::error::{Error, EvidenceFault};
use super::probe::Probe;
use super::wire;
use super::wire::{decode_response, decode_tcp_frame};
use super::{AttemptEvidence, MessageLimits, Outcome, ValidatedResponse};

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
        11 => "dso_type_not_implemented",
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
#[derive(Clone, Debug, PartialEq)]
pub enum ResponseClassification {
    Response(ValidatedResponse),
    /// A wire error the caller can match on; `reason` keeps its message for
    /// the report, and a correlation refusal that is not a wire failure has
    /// no source.
    Unrelated {
        reason: String,
        source: Option<wire::Error>,
    },
    DecodeFailure {
        reason: String,
        source: Option<wire::Error>,
    },
    NetworkFailure {
        reason: String,
    },
}

impl ResponseClassification {
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
    if let Some(observation) = correlation::observe(registry, ProbeTransport::Udp, sent, response)
        && observation.correlation.is_network_failure()
    {
        return Some(ResponseClassification::NetworkFailure {
            reason: observation.reason.to_owned(),
        });
    }
    if direct_udp_match(sent, &response.packet) {
        if response
            .diagnostics
            .iter()
            .any(Diagnostic::is_checksum_failure)
        {
            return Some(ResponseClassification::DecodeFailure {
                reason: "correlated UDP response has an invalid checksum diagnostic".to_owned(),
                source: None,
            });
        }
        let Some(payload) = dns_payload(&response.packet) else {
            return Some(ResponseClassification::DecodeFailure {
                reason: "correlated UDP response has no complete DNS payload".to_owned(),
                source: None,
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
                    source: Some(error),
                },
                Err(error) => ResponseClassification::DecodeFailure {
                    reason: error.to_string(),
                    source: Some(error),
                },
            },
        );
    }

    None
}

/// The sent packet carries a typed DNS layer, which owns registry-level
/// matching for the pair; this workflow correlates replies at the UDP tuple
/// and leaves every application check to [`decode_response`].
fn direct_udp_match(request: &Packet, response: &Packet) -> bool {
    transport_tuple_reversed(request, response, BuiltinProtocol::Udp).is_some()
}

pub(crate) fn dns_payload(packet: &Packet) -> Option<Bytes> {
    let (udp_index, udp) = packet
        .iter()
        .enumerate()
        .find_map(|(index, layer)| Some((index, layer.downcast_ref::<Udp>()?)))?;
    let port_53 = udp.source_port == 53 || udp.destination_port == 53;
    let payload = packet.layer(udp_index.checked_add(1)?)?;
    match BuiltinProtocol::of(payload) {
        Some(BuiltinProtocol::Dns) if port_53 => {
            payload.downcast_ref::<Dns>().map(|dns| dns.wire().clone())
        }
        Some(BuiltinProtocol::Malformed) if port_53 => payload
            .downcast_ref::<packetcraftr_core::layer::Malformed>()
            .filter(|layer| layer.intended_protocol.as_deref() == Some("dns"))
            .map(|layer| layer.bytes.clone()),
        Some(BuiltinProtocol::Raw) => payload.downcast_ref::<Raw>().map(|raw| raw.bytes.clone()),
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
                    response_code_name(response.metadata.response_code)
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
        ResponseClassification::DecodeFailure { reason, .. } => AttemptClassification::Failed {
            status: Outcome::DecodeFailure,
            reason,
        },
        ResponseClassification::Unrelated { reason, .. } => AttemptClassification::Failed {
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
    evidence: &mut EvidenceState,
) -> ClassifiedAttempt {
    let response_frame = evidence.retain_response(&candidate.decoded.frame);
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
        evidence: crate::dns::AttemptEvidence {
            attempt: probe.attempt,
            server_address: probe.server_address,
            status,
            received_at: candidate.decoded.frame.timestamp,
            latency: Some(candidate.latency),
            response_code,
            reason,
            transport_evidence: crate::dns::TransportEvidence::Udp {
                source_port: probe.source_port,
                sent_at,
                response: response_frame,
            },
        },
        response,
    }
}

pub(super) fn timeout_evidence(probe: &Probe, sent_at: SystemTime) -> ClassifiedAttempt {
    ClassifiedAttempt {
        evidence: crate::dns::AttemptEvidence {
            attempt: probe.attempt,
            server_address: probe.server_address,
            status: Outcome::Timeout,
            received_at: None,
            latency: None,
            response_code: None,
            reason: "no checksum-valid, tuple-correlated DNS response before the deadline"
                .to_owned(),
            transport_evidence: crate::dns::TransportEvidence::Udp {
                source_port: probe.source_port,
                sent_at,
                response: None,
            },
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
        evidence: crate::dns::AttemptEvidence {
            attempt: probe.attempt,
            server_address: probe.server_address,
            status,
            received_at: None,
            latency: None,
            response_code: None,
            reason,
            transport_evidence: crate::dns::TransportEvidence::Tcp {
                source_port: None,
                sent_at: None,
            },
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
    response: crate::dns::tcp::Response,
    limits: MessageLimits,
) -> Result<ClassifiedAttempt, Error> {
    let expected_written = probe
        .query
        .len()
        .checked_add(2)
        .ok_or(Error::InvalidEvidence {
            attempt: probe.attempt,
            fault: EvidenceFault::TcpQueryLengthOverflow,
        })?;
    if response.local_address.port() == 0
        || response.peer_address != SocketAddr::new(probe.server_address, probe.server_port)
        || response.bytes_written != expected_written
        || response.elapsed > timeout
        || response.latency > response.elapsed
    {
        return Err(Error::InvalidEvidence {
            attempt: probe.attempt,
            fault: EvidenceFault::TcpReceipt,
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
                response_code_name(validated.metadata.response_code)
            ),
            Some(validated),
        ),
        Err(error) if error.is_unrelated() => (Outcome::Unrelated, None, error.to_string(), None),
        Err(error) => (Outcome::DecodeFailure, None, error.to_string(), None),
    };
    Ok(ClassifiedAttempt {
        evidence: crate::dns::AttemptEvidence {
            attempt: probe.attempt,
            server_address: probe.server_address,
            status,
            received_at: Some(response.received_at),
            latency: Some(response.latency),
            response_code,
            reason,
            transport_evidence: crate::dns::TransportEvidence::Tcp {
                source_port: Some(response.local_address.port()),
                sent_at: Some(response.sent_at),
            },
        },
        response: validated,
    })
}

#[cfg(test)]
mod tests {
    use super::response_code_name;

    #[test]
    fn response_code_names_include_the_dso_type_code() {
        assert_eq!(response_code_name(10), "not_zone");
        assert_eq!(response_code_name(11), "dso_type_not_implemented");
        assert_eq!(response_code_name(12), "unknown");
    }
}
