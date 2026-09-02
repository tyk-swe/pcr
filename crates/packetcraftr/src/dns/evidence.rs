// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact DNS executor-evidence validation and accounting errors.

use std::time::Duration;

use packetcraftr_core::{Packet, codec::NetworkEnvelope, protocol::BuiltinProtocol};

use crate::probe::evidence::{
    ExchangeEvidenceError, format_exchange_evidence_error, validate_aggregate_evidence_limits,
    validate_capture_statistics_evidence, validate_response_frames_and_deadlines,
    validate_sent_byte_accounting,
};

use super::classification::dns_payload;
use super::error::Error;
use super::model::{Execution, Limits, Probe};

pub(super) fn validate_dns_execution(
    probe: &Probe,
    execution: &Execution,
    limits: Limits,
    timeout: Duration,
) -> Result<(), Error> {
    let attempt = probe.attempt;
    let sent_packet = &execution.sent.built().packet;
    let Some(network) = dns_network_envelope(sent_packet) else {
        return Err(Error::InvalidEvidence {
            attempt,
            message: "sent packet has no IPv4 or IPv6 tuple".to_owned(),
        });
    };
    let Some(ports) = dns_udp_ports(sent_packet) else {
        return Err(Error::InvalidEvidence {
            attempt,
            message: "sent packet has no complete UDP tuple".to_owned(),
        });
    };
    let network_protocol = if probe.server_address.is_ipv4() {
        BuiltinProtocol::Ipv4
    } else {
        BuiltinProtocol::Ipv6
    };
    let network_index = execution
        .sent
        .built()
        .packet
        .iter()
        .next()
        .filter(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ethernet))
        .map_or(0usize, |_| 1);
    if sent_packet.len() != network_index.saturating_add(3)
        || !execution
            .sent
            .built()
            .packet
            .iter()
            .nth(network_index)
            .is_some_and(|layer| BuiltinProtocol::of(layer) == Some(network_protocol))
        || !execution
            .sent
            .built()
            .packet
            .iter()
            .nth(network_index.saturating_add(1))
            .is_some_and(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Udp))
        || dns_payload(sent_packet).as_deref() != Some(probe.query.as_ref())
        || network.destination != probe.server_address
        || ports.source != probe.source_port
        || ports.destination != probe.server_port
    {
        return Err(Error::InvalidEvidence {
            attempt,
            message: "sent packet does not preserve the authorized server, UDP ports, and exact DNS query"
                .to_owned(),
        });
    }
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(Error::InvalidEvidence {
            attempt,
            message: "successful exchange statistics must account for exactly one DNS query"
                .to_owned(),
        });
    }
    if execution
        .responses
        .iter()
        .any(|response| response.request_index != 0)
    {
        return Err(Error::InvalidEvidence {
            attempt,
            message: "single-query DNS exchange returned a response for an unknown request index"
                .to_owned(),
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

fn map_dns_evidence_error(attempt: u32, error: ExchangeEvidenceError) -> Error {
    Error::InvalidEvidence {
        attempt,
        message: format_exchange_evidence_error(error, "DNS exchange", "DNS"),
    }
}

fn dns_network_envelope(packet: &Packet) -> Option<NetworkEnvelope> {
    let path = packetcraftr_core::packet::semantics::outer_ip_path(packet).ok()??;
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
    let udp = packetcraftr_core::packet::semantics::transport_key(udp)?;
    Some(UdpPorts {
        source: udp.source_port,
        destination: udp.destination_port,
    })
}
