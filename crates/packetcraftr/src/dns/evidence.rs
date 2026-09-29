// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::protocol::{BuiltinProtocol, transport_tuple_reversed};
use packetcraftr_core::{
    codec::NetworkEnvelope, decode::DecodedPacket, diagnostic::Diagnostic, layer::Raw,
    packet::Packet, registry::Registry,
};

use crate::correlation::{self, Transport as ProbeTransport};
use crate::execution::evidence::{EvidenceState, ResponseCandidate};
use crate::execution::validation::{
    validate_aggregate_evidence_limits, validate_capture_statistics_evidence,
    validate_response_frames_and_deadlines, validate_sent_byte_accounting,
};

use super::error::{Error, EvidenceFault};
use super::executor::ExchangeEvidence;
use super::plan::Probe;
use super::wire;
use super::wire::{decode_response, decode_tcp_frame};
use super::{AttemptEvidence, Limits, MessageLimits, Outcome, ValidatedResponse};

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

/// Invalid correlated frames are decode failures, never accepted responses.
#[derive(Clone, Debug, PartialEq)]
pub enum ResponseClassification {
    Response(ValidatedResponse),
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

/// Correlates at the UDP tuple; [`decode_response`] owns every application check.
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

pub(super) struct ClassifiedAttempt {
    pub(super) evidence: AttemptEvidence,
    pub(super) response: Option<ValidatedResponse>,
}

pub(super) fn candidate_evidence(
    probe: &Probe,
    sent_at: SystemTime,
    candidate: ResponseCandidate<'_, ResponseClassification>,
    evidence: &mut EvidenceState,
) -> ClassifiedAttempt {
    let response_frame = evidence.retain_response(&candidate.decoded.frame);
    let status = candidate.observation.outcome();
    let (response_code, reason, response) = match candidate.observation {
        ResponseClassification::Response(response) => {
            let reason = if response.metadata.truncated {
                "validated DNS response set the truncation flag; partial records were not accepted"
                    .to_owned()
            } else {
                format!(
                    "validated DNS response with code {}",
                    response_code_name(response.metadata.response_code)
                )
            };
            (
                Some(response.metadata.response_code),
                reason,
                Some(response),
            )
        }
        ResponseClassification::NetworkFailure { reason }
        | ResponseClassification::DecodeFailure { reason, .. }
        | ResponseClassification::Unrelated { reason, .. } => (None, reason, None),
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

/// TCP socket bytes are never represented as captured frame evidence.
pub(super) fn classify_tcp_response(
    probe: &Probe,
    timeout: Duration,
    response: crate::dns::tcp::Response,
    limits: MessageLimits,
) -> Result<ClassifiedAttempt, Error> {
    if response.local_address.port() == 0
        || response.peer_address != SocketAddr::new(probe.server_address, probe.server_port)
        || response.bytes_written != probe.framed_query_bytes()
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

pub(super) fn validate_dns_execution(
    probe: &Probe,
    execution: &ExchangeEvidence,
    limits: Limits,
    timeout: Duration,
) -> Result<(), Error> {
    let attempt = probe.attempt;
    let sent_packet = &execution.sent.built().packet;
    let Some(network) = dns_network_envelope(sent_packet) else {
        return Err(Error::InvalidEvidence {
            attempt,
            fault: EvidenceFault::SentWithoutNetwork,
        });
    };
    let Some(ports) = dns_udp_ports(sent_packet) else {
        return Err(Error::InvalidEvidence {
            attempt,
            fault: EvidenceFault::SentWithoutUdp,
        });
    };
    let network_protocol = if probe.server_address.is_ipv4() {
        BuiltinProtocol::Ipv4
    } else {
        BuiltinProtocol::Ipv6
    };
    if !correlation::packet_shape_with_payload_matches(
        sent_packet,
        &[network_protocol, BuiltinProtocol::Udp],
    ) || dns_payload(sent_packet).as_deref() != Some(probe.query.as_ref())
        || network.destination != probe.server_address
        || ports.source != probe.source_port
        || ports.destination != probe.server_port
    {
        return Err(Error::InvalidEvidence {
            attempt,
            fault: EvidenceFault::SentQueryChanged,
        });
    }
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(Error::InvalidEvidence {
            attempt,
            fault: EvidenceFault::SentCount,
        });
    }
    if execution
        .responses
        .iter()
        .any(|response| response.request_index != 0)
    {
        return Err(Error::InvalidEvidence {
            attempt,
            fault: EvidenceFault::ResponseOutsideQuery,
        });
    }
    validate_sent_byte_accounting(std::slice::from_ref(&execution.sent), execution.stats.bytes)
        .map_err(|error| map_dns_evidence_error(attempt, error))?;
    validate_capture_statistics_evidence(execution.stats.capture)
        .map_err(|error| map_dns_evidence_error(attempt, error))?;
    validate_response_frames_and_deadlines(&execution.responses, &execution.unsolicited, timeout)
        .map_err(|error| map_dns_evidence_error(attempt, error))?;
    validate_aggregate_evidence_limits(
        &execution.responses,
        &execution.unsolicited,
        &execution.undecoded,
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
    )
    .map_err(|error| map_dns_evidence_error(attempt, error))?;
    Ok(())
}

fn map_dns_evidence_error(attempt: u32, error: crate::evidence::Error) -> Error {
    Error::InvalidEvidence {
        attempt,
        fault: EvidenceFault::Exchange(error),
    }
}

fn dns_network_envelope(packet: &Packet) -> Option<NetworkEnvelope> {
    let path = packetcraftr_core::protocol::semantics::outer_ip_path(packet).ok()??;
    Some(NetworkEnvelope {
        source: path.source,
        destination: path.header_destination,
    })
}

struct UdpPorts {
    source: u16,
    destination: u16,
}

fn dns_udp_ports(packet: &Packet) -> Option<UdpPorts> {
    let udp = packet
        .iter()
        .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Udp))?;
    let udp = packetcraftr_core::protocol::semantics::transport_key(udp)?;
    Some(UdpPorts {
        source: udp.source_port,
        destination: udp.destination_port,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::protocol::link::Ethernet;

    use super::*;
    use crate::Stats;
    use crate::dns::{QueryType, ResponseMetadata};
    use crate::evidence::ExecutionPermit;
    use crate::execution::evidence::EvidenceState;

    #[test]
    fn response_code_names_include_the_dso_type_code() {
        assert_eq!(response_code_name(10), "not_zone");
        assert_eq!(response_code_name(11), "dso_type_not_implemented");
        assert_eq!(response_code_name(12), "unknown");
    }

    fn probe() -> Probe {
        Probe {
            attempt: 1,
            server_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            server_port: 5353,
            source_port: 40_000,
            transaction_id: 0x1234,
            query_name: "example.test".to_owned(),
            query_type: QueryType::A,
            query: Bytes::from_static(b"query"),
        }
    }

    fn validate(probe: &Probe, sent: Packet) -> Result<(), Error> {
        let sent = crate::test_support::sent_packet(sent);
        let bytes = u64::try_from(sent.bytes_sent()).unwrap();
        let execution = ExchangeEvidence {
            permit: ExecutionPermit::new(),
            sent,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes,
                elapsed: Duration::from_millis(1),
                ..Stats::default()
            },
        };
        validate_dns_execution(probe, &execution, Limits::default(), Duration::from_secs(1))
    }

    fn fault(result: Result<(), Error>) -> EvidenceFault {
        match result {
            Err(Error::InvalidEvidence { fault, .. }) => fault,
            other => panic!("expected invalid evidence, got {other:?}"),
        }
    }

    #[test]
    fn a_sent_query_that_keeps_the_probe_shape_is_valid() {
        let probe = probe();
        validate(&probe, probe.packet()).expect("probe packet is valid evidence");
    }

    #[test]
    fn a_leading_ethernet_layer_does_not_change_the_query_shape() {
        let probe = probe();
        let mut sent = probe.packet();
        sent.insert(0, Ethernet::default()).unwrap();
        validate(&probe, sent).expect("link header is outside the query shape");
    }

    #[test]
    fn a_sent_query_with_an_extra_or_missing_payload_layer_is_changed() {
        let probe = probe();
        let mut extra = probe.packet();
        extra.push(Raw::new(Bytes::from_static(b"trailer")));
        assert_eq!(
            fault(validate(&probe, extra)),
            EvidenceFault::SentQueryChanged
        );

        let mut missing = probe.packet();
        missing.remove(2).unwrap();
        assert_eq!(
            fault(validate(&probe, missing)),
            EvidenceFault::SentQueryChanged
        );
    }

    #[test]
    fn a_sent_query_whose_payload_layer_cannot_carry_dns_is_changed() {
        let probe = Probe {
            server_port: 123,
            ..probe()
        };
        let mut other = probe.packet();
        other.remove(2).unwrap();
        other.push(packetcraftr_core::protocol::application::ntp::Ntp::default());
        assert_eq!(
            fault(validate(&probe, other)),
            EvidenceFault::SentQueryChanged
        );
    }

    #[test]
    fn a_sent_query_with_different_bytes_is_changed() {
        let probe = probe();
        let mut other = probe.clone();
        other.query = Bytes::from_static(b"other");
        assert_eq!(
            fault(validate(&probe, other.packet())),
            EvidenceFault::SentQueryChanged
        );
    }

    #[test]
    fn a_sent_packet_without_udp_is_reported_before_the_shape_check() {
        let probe = probe();
        let mut without_udp = probe.packet();
        without_udp.remove(2).unwrap();
        without_udp.remove(1).unwrap();
        assert_eq!(
            fault(validate(&probe, without_udp)),
            EvidenceFault::SentWithoutUdp
        );
    }

    fn validated(response_code: u16, truncated: bool) -> ResponseClassification {
        ResponseClassification::Response(ValidatedResponse {
            metadata: ResponseMetadata {
                response_code,
                edns: None,
                authoritative: false,
                truncated,
                recursion_desired: true,
                recursion_available: true,
                authenticated_data: false,
                checking_disabled: false,
                rejected_record_count: 0,
            },
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: Vec::new(),
        })
    }

    #[test]
    fn a_classified_response_states_its_status_code_and_reason() {
        let bytes = Bytes::from_static(&[0xff]);
        let decoded = DecodedPacket {
            packet: Packet::new(),
            frame: Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap(),
            layout: Default::default(),
            diagnostics: Vec::new(),
        };
        let reason = |text: &str| text.to_owned();
        for (observation, status, code, expected) in [
            (
                validated(3, false),
                Outcome::Response,
                Some(3),
                "validated DNS response with code name_error",
            ),
            (
                validated(0, true),
                Outcome::Truncated,
                Some(0),
                "validated DNS response set the truncation flag; partial records were not accepted",
            ),
            (
                ResponseClassification::NetworkFailure {
                    reason: reason("port unreachable"),
                },
                Outcome::NetworkFailure,
                None,
                "port unreachable",
            ),
            (
                ResponseClassification::DecodeFailure {
                    reason: reason("bad checksum"),
                    source: None,
                },
                Outcome::DecodeFailure,
                None,
                "bad checksum",
            ),
            (
                ResponseClassification::Unrelated {
                    reason: reason("other transaction"),
                    source: None,
                },
                Outcome::Unrelated,
                None,
                "other transaction",
            ),
        ] {
            let expects_response = code.is_some();
            let mut state = EvidenceState::new(
                Limits::default().evidence(),
                crate::dns::EVIDENCE_DIAGNOSTICS,
            );
            let attempt = candidate_evidence(
                &probe(),
                UNIX_EPOCH,
                ResponseCandidate {
                    observation,
                    decoded: &decoded,
                    latency: Duration::from_millis(1),
                },
                &mut state,
            );
            assert_eq!(attempt.evidence.status, status);
            assert_eq!(attempt.evidence.response_code, code);
            assert_eq!(attempt.evidence.reason, expected);
            assert_eq!(attempt.response.is_some(), expects_response);
        }
    }
}
