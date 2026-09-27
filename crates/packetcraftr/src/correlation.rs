// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Wire correlation and probe identity shared by every workflow that reads
//! captured responses against the packets it sent: DNS, scan, and traceroute.
//!
//! [`observe`] correlates one decoded response with a request without
//! assigning a workflow status; the identity helpers make probes
//! distinguishable on the wire so that correlation can succeed.

use std::net::IpAddr;

use bytes::Bytes;
use packetcraftr_core::protocol::{
    IcmpErrorKind, QuotedTransport, quoted_icmp_error, transport::Tcp, transport_tuple_reversed,
};
use packetcraftr_core::{
    decode::DecodedPacket, diagnostic::Diagnostic, packet::Packet, protocol::BuiltinProtocol,
    protocol::semantics, registry::Registry,
};
use serde::{Deserialize, Serialize};

/// The wire protocol a probe is sent over, as a request names it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    /// The traceroute default.
    #[default]
    Udp,
    Icmp,
}

impl Transport {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Maps an operation-local sequence to an IPv4 identification that native
/// raw-socket adapters can preserve exactly. Zero is deliberately excluded.
pub(crate) const fn nonzero_ipv4_identification(sequence: u64) -> u16 {
    ((sequence % u16::MAX as u64) + 1) as u16
}

/// ICMP echo payload identifying one probe: `P`, the workflow's `tag`, and the
/// sequence deliberately reduced to 16 bits across the last two bytes.
/// Sent-probe matching rebuilds the payload, so the reduction is symmetric.
pub(crate) fn icmp_identity(tag: u8, sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, tag, (sequence >> 8) as u8, sequence as u8])
}

/// First port of the IANA dynamic range, the base every workflow rotates
/// ephemeral source ports through.
pub(crate) const EPHEMERAL_SOURCE_PORT_BASE: u16 = 49_152;

/// Rotates an ephemeral source port `offset` steps from `base`, staying inside
/// whichever range `base` already belongs to: the dynamic range at or above
/// [`EPHEMERAL_SOURCE_PORT_BASE`], or ports `1..EPHEMERAL_SOURCE_PORT_BASE`
/// when the caller pinned a lower port.
// both ranges start inside u16 and `rotated` is a remainder modulo the range width, so `range_start
// + rotated` stays at or below u16::MAX; `offset` is likewise reduced modulo that width before the
// narrowing
pub(crate) fn ephemeral_source_port(base: u16, offset: u64) -> u16 {
    let (range_start, width) = if base >= EPHEMERAL_SOURCE_PORT_BASE {
        (
            u32::from(EPHEMERAL_SOURCE_PORT_BASE),
            u32::from(u16::MAX)
                .saturating_sub(u32::from(EPHEMERAL_SOURCE_PORT_BASE))
                .saturating_add(1),
        )
    } else {
        (1, u32::from(EPHEMERAL_SOURCE_PORT_BASE).saturating_sub(1))
    };
    let offset = offset.checked_rem(u64::from(width)).unwrap_or(0) as u32;
    let rotated = u32::from(base)
        .saturating_sub(range_start)
        .saturating_add(offset)
        .checked_rem(width)
        .unwrap_or(0);
    range_start.saturating_add(rotated) as u16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Correlation {
    TcpReset,
    TcpSynAck,
    TcpOther,
    UdpReply,
    IcmpReply,
    PortUnreachable,
    TimeExceeded,
    AdministrativelyProhibited,
    DestinationUnreachable,
}

impl Correlation {
    pub(crate) const fn is_direct_reply(self) -> bool {
        matches!(
            self,
            Self::TcpReset | Self::TcpSynAck | Self::TcpOther | Self::UdpReply | Self::IcmpReply
        )
    }

    pub(crate) const fn is_network_failure(self) -> bool {
        !self.is_direct_reply()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub(crate) responder: IpAddr,
    pub(crate) reason: &'static str,
    pub(crate) correlation: Correlation,
}

impl Observation {
    const fn new(responder: IpAddr, correlation: Correlation, reason: &'static str) -> Self {
        Self {
            responder,
            reason,
            correlation,
        }
    }
}

pub(crate) fn packet_shape_matches(packet: &Packet, expected: &[BuiltinProtocol]) -> bool {
    let mut layers = packet.iter().peekable();
    if layers
        .peek()
        .is_some_and(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Ethernet))
    {
        layers.next();
    }
    expected.iter().all(|expected| {
        layers
            .next()
            .is_some_and(|layer| BuiltinProtocol::of(layer) == Some(*expected))
    }) && layers.next().is_none()
}

/// Correlates one decoded response with a request without assigning an
/// operation-specific status. Corrupt and unrelated traffic returns `None`.
pub(crate) fn observe(
    registry: &Registry,
    transport: Transport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<Observation> {
    if response
        .diagnostics
        .iter()
        .any(Diagnostic::is_checksum_failure)
    {
        return None;
    }
    let responder = semantics::outer_ip_path(&response.packet).ok()??.source;
    if let Some(observation) = classify_icmp_error(transport, request, &response.packet, responder)
    {
        return Some(observation);
    }
    // UDP probes leave DNS identity to the workflow, but still require the
    // entire tunnel stack to reverse. Other deepest protocols retain their
    // registry matcher, including TCP sequence and ICMP echo identity checks.
    let udp_responder = (transport == Transport::Udp)
        .then(|| transport_tuple_reversed(request, &response.packet, BuiltinProtocol::Udp))
        .flatten();
    let (direct_reply, direct_responder) = if let Some(responder) = udp_responder {
        (true, Some(responder))
    } else {
        match request
            .iter()
            .filter_map(|layer| registry.matcher(layer.protocol_id().as_str()))
            .filter_map(|matcher| {
                let matched = matcher.matches(request, &response.packet)?;
                Some((matcher, matched))
            })
            .max_by_key(|(_, matched)| matched.confidence)
        {
            Some((matcher, _)) => (true, matcher.responder(request, &response.packet)),
            None => (false, None),
        }
    };
    if direct_reply {
        let responder = direct_responder.unwrap_or(responder);
        let observation = match transport {
            Transport::Tcp => {
                let tcp = response.packet.get::<Tcp>()?;
                let flags = tcp.flags;
                if flags & Tcp::RST != 0 {
                    Observation::new(responder, Correlation::TcpReset, "correlated TCP reset")
                } else if flags & (Tcp::SYN | Tcp::ACK) == (Tcp::SYN | Tcp::ACK) {
                    let request_tcp = request.get::<Tcp>()?;
                    if tcp.acknowledgment != request_tcp.sequence.wrapping_add(1) {
                        return None;
                    }
                    Observation::new(responder, Correlation::TcpSynAck, "correlated TCP SYN/ACK")
                } else {
                    Observation::new(
                        responder,
                        Correlation::TcpOther,
                        "correlated TCP response with inconclusive flags",
                    )
                }
            }
            Transport::Udp => Observation::new(
                responder,
                Correlation::UdpReply,
                "correlated UDP response from the requested endpoint",
            ),
            Transport::Icmp => Observation::new(
                responder,
                Correlation::IcmpReply,
                "correlated ICMP echo reply",
            ),
        };
        return Some(observation);
    }

    None
}

fn classify_icmp_error(
    transport: Transport,
    request: &Packet,
    response: &Packet,
    responder: IpAddr,
) -> Option<Observation> {
    let expected_transport = match transport {
        Transport::Tcp => QuotedTransport::Tcp,
        Transport::Udp => QuotedTransport::Udp,
        Transport::Icmp => QuotedTransport::Icmp,
    };
    let kind = quoted_icmp_error(request, response, expected_transport)?;
    let icmp_protocol = response
        .iter()
        .find_map(|layer| match BuiltinProtocol::of(layer) {
            Some(protocol @ (BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6)) => Some(protocol),
            _ => None,
        })?;
    let ipv6 = icmp_protocol == BuiltinProtocol::Icmpv6;
    let (correlation, ipv4_reason, ipv6_reason) = match kind {
        IcmpErrorKind::PortUnreachable => (
            Correlation::PortUnreachable,
            "ICMPv4 port unreachable",
            "ICMPv6 port unreachable",
        ),
        IcmpErrorKind::AdministrativelyProhibited => (
            Correlation::AdministrativelyProhibited,
            "ICMPv4 administratively prohibited",
            "ICMPv6 policy or administrative rejection",
        ),
        IcmpErrorKind::DestinationUnreachable => (
            Correlation::DestinationUnreachable,
            "ICMPv4 destination unreachable",
            "ICMPv6 destination unreachable",
        ),
        IcmpErrorKind::TimeExceeded => (
            Correlation::TimeExceeded,
            "ICMPv4 time exceeded before reaching the endpoint",
            "ICMPv6 time exceeded before reaching the endpoint",
        ),
    };
    let reason = if ipv6 { ipv6_reason } else { ipv4_reason };
    Some(Observation::new(responder, correlation, reason))
}

#[cfg(test)]
mod tests {

    use super::{EPHEMERAL_SOURCE_PORT_BASE, ephemeral_source_port};

    #[test]
    fn dynamic_range_offsets_wrap_at_the_top_of_the_range() {
        let width = u64::from(u16::MAX) - u64::from(EPHEMERAL_SOURCE_PORT_BASE) + 1;
        for offset in [0, 1, 2, width - 1, width, width + 3, u64::MAX] {
            assert_eq!(
                ephemeral_source_port(EPHEMERAL_SOURCE_PORT_BASE, offset),
                u16::try_from(u64::from(EPHEMERAL_SOURCE_PORT_BASE) + offset % width).unwrap(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn a_dynamic_base_rotates_inside_the_dynamic_range() {
        let width = u32::from(u16::MAX) - u32::from(EPHEMERAL_SOURCE_PORT_BASE) + 1;
        assert_eq!(ephemeral_source_port(50_000, 0), 50_000);
        assert_eq!(ephemeral_source_port(50_000, 7), 50_007);
        assert_eq!(
            ephemeral_source_port(u16::MAX, 1),
            EPHEMERAL_SOURCE_PORT_BASE
        );
        assert_eq!(
            ephemeral_source_port(EPHEMERAL_SOURCE_PORT_BASE, u64::from(width) - 1),
            u16::MAX
        );
        for offset in 0..u64::from(width) {
            assert!(ephemeral_source_port(60_000, offset) >= EPHEMERAL_SOURCE_PORT_BASE);
        }
    }

    /// A base below the dynamic range rotates within
    /// `1..EPHEMERAL_SOURCE_PORT_BASE`, so a pinned low port never escapes into
    /// the dynamic range.
    #[test]
    fn a_low_base_rotates_below_the_dynamic_range() {
        let width = u32::from(EPHEMERAL_SOURCE_PORT_BASE) - 1;
        assert_eq!(ephemeral_source_port(53, 0), 53);
        assert_eq!(ephemeral_source_port(53, 4), 57);
        assert_eq!(ephemeral_source_port(0, 0), 1);
        assert_eq!(
            ephemeral_source_port(1, u64::from(width) - 1),
            EPHEMERAL_SOURCE_PORT_BASE - 1
        );
        assert_eq!(ephemeral_source_port(EPHEMERAL_SOURCE_PORT_BASE - 1, 1), 1);
        for offset in [0_u64, 1, 4_096, u64::from(width) + 11, u64::MAX] {
            let port = ephemeral_source_port(1_024, offset);
            assert!(
                (1..EPHEMERAL_SOURCE_PORT_BASE).contains(&port),
                "offset {offset} produced {port}"
            );
        }
    }
}
