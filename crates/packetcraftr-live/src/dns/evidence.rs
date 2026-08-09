// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact DNS executor-evidence validation and accounting errors.

use std::time::Duration;

use packetcraftr_packet::{
    Packet, codec::NetworkEnvelope, decode::Result as DecodedPacket, semantics::BuiltinProtocol,
};

use crate::probe::evidence::{
    ExchangeEvidence, ExchangeEvidenceError, MatchedResponseEvidence, ResponseEvidence,
    validate_exchange_evidence as validate_shared_exchange_evidence,
};

use super::error::DnsError;
use super::model::{DnsExchangeExecution, DnsLimits, DnsMatchedResponse, DnsProbe};
use super::wire::dns_payload;

impl ResponseEvidence for DnsMatchedResponse {
    fn response(&self) -> &DecodedPacket {
        self.inner.response()
    }

    fn latency(&self) -> std::time::Duration {
        self.inner.latency()
    }

    fn record_id(&self) -> packetcraftr_network::capture::CaptureRecordId {
        self.inner.record_id()
    }

    fn received_at(&self) -> std::time::Instant {
        self.inner.received_at()
    }
}

impl MatchedResponseEvidence for DnsMatchedResponse {
    fn request_index(&self) -> usize {
        self.inner.request_index()
    }
}

pub(super) fn validate_dns_execution(
    probe: &DnsProbe,
    execution: &DnsExchangeExecution,
    limits: DnsLimits,
    timeout: Duration,
) -> Result<(), DnsError> {
    let attempt = probe.attempt;
    let Some(network) = dns_network_envelope(execution.sent.packet()) else {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet has no IPv4 or IPv6 tuple".to_owned(),
        });
    };
    let Some(ports) = dns_udp_ports(execution.sent.packet()) else {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet has no complete UDP tuple".to_owned(),
        });
    };
    let network_protocol = if probe.server_address.is_ipv4() {
        BuiltinProtocol::Ipv4
    } else {
        BuiltinProtocol::Ipv6
    };
    let packet = execution.sent.packet();
    let network_index = packet
        .iter()
        .next()
        .filter(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ethernet))
        .map_or(0, |_| 1);
    if packet.len() != network_index + 3
        || !packet
            .iter()
            .nth(network_index)
            .is_some_and(|layer| BuiltinProtocol::of(layer) == Some(network_protocol))
        || !packet
            .iter()
            .nth(network_index + 1)
            .is_some_and(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Udp))
        || dns_payload(packet).as_deref() != Some(probe.query.as_ref())
        || network.destination != probe.server_address
        || ports.source != probe.source_port
        || ports.destination != probe.server_port
    {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet does not preserve the authorized server, UDP ports, and exact DNS query"
                .to_owned(),
        });
    }
    validate_shared_exchange_evidence(
        ExchangeEvidence {
            request_count: 1,
            sent: std::slice::from_ref(&execution.sent),
            matched_responses: &execution.responses,
            unsolicited: &execution.unsolicited,
            undecoded: &execution.undecoded,
            timeout,
            stats: &execution.stats,
        },
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        |_, _| true,
    )
    .map_err(|error| map_dns_evidence_error(attempt, error))?;
    Ok(())
}

fn map_dns_evidence_error(attempt: u32, error: ExchangeEvidenceError) -> DnsError {
    let message = match error {
        ExchangeEvidenceError::CapturedFrameCountOverflow => {
            "executor frame-count accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedFrameLimitExceeded { actual, limit } => {
            format!("executor returned {actual} frames beyond max_evidence_frames={limit}")
        }
        ExchangeEvidenceError::CapturedByteCountOverflow => {
            "executor frame-byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedByteLimitExceeded { actual, limit } => {
            format!("executor returned {actual} frame bytes beyond max_evidence_bytes={limit}")
        }
        ExchangeEvidenceError::SentByteCountOverflow => {
            "sent frame byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::SentByteCountMismatch { reported, actual } => format!(
            "successful exchange reported {reported} sent bytes for {actual} exact frame bytes"
        ),
        ExchangeEvidenceError::InvalidMatchedResponse { message }
        | ExchangeEvidenceError::InvalidUnsolicitedResponse { message }
        | ExchangeEvidenceError::InvalidCaptureStatistics { message } => message,
        ExchangeEvidenceError::MatchedResponseAfterTimeout { latency, timeout } => {
            format!("matched response latency {latency:?} exceeds timeout {timeout:?}")
        }
        ExchangeEvidenceError::SentCardinality { .. }
        | ExchangeEvidenceError::MatchedResponseOutsideBatch
        | ExchangeEvidenceError::SentPacketMismatch { .. }
        | ExchangeEvidenceError::IncompleteStatistics
        | ExchangeEvidenceError::DuplicateCaptureRecord { .. }
        | ExchangeEvidenceError::ContradictoryTiming { .. } => {
            unreachable!("DNS validation does not produce batch-only evidence errors")
        }
    };
    DnsError::InvalidEvidence { attempt, message }
}

fn dns_network_envelope(packet: &Packet) -> Option<NetworkEnvelope> {
    let path = packetcraftr_packet::semantics::outer_ip_path(packet).ok()??;
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
    let udp = packetcraftr_packet::semantics::transport_key(udp)?;
    Some(UdpPorts {
        source: udp.source_port,
        destination: udp.destination_port,
    })
}
