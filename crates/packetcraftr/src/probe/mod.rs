// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The lifecycle, vocabulary, and wire correlation shared by probe workflows.

pub(crate) mod client_executor;
mod error;
pub(crate) mod evidence;
mod model;
pub(crate) mod runner;

pub use error::{Error, ErrorKind, Workflow};
pub use model::{ProbeEndpoint, ProbeStatus, Transport};
pub use runner::{Batch, Execution, Executor};

use std::net::IpAddr;

use packetcraftr_core::protocol::{
    QuotedIcmpError, QuotedProbeTransport, quoted_icmp_error_kind, transport::Tcp,
};
use packetcraftr_core::{
    Packet, decode::DecodedPacket, diagnostic::Diagnostic, packet::semantics,
    protocol::BuiltinProtocol, registry::Registry,
};

/// Maps an operation-local sequence to an IPv4 identification that native
/// raw-socket adapters can preserve exactly. Zero is deliberately excluded.
#[expect(
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    reason = "`u16::MAX` is a non-zero divisor and the remainder is strictly below it, so the \
              increment neither divides by zero nor overflows u16"
)]
pub(crate) const fn nonzero_ipv4_identification(sequence: u64) -> u16 {
    ((sequence % u16::MAX as u64) + 1) as u16
}

/// First port of the IANA dynamic range, the base every workflow rotates
/// ephemeral source ports through.
pub const EPHEMERAL_SOURCE_PORT_BASE: u16 = 49_152;

/// Rotates an ephemeral source port `offset` steps from `base`, staying inside
/// whichever range `base` already belongs to: the dynamic range at or above
/// [`EPHEMERAL_SOURCE_PORT_BASE`], or ports `1..EPHEMERAL_SOURCE_PORT_BASE`
/// when the caller pinned a lower port.
#[expect(
    clippy::cast_possible_truncation,
    reason = "both ranges start inside u16 and `rotated` is a remainder modulo the range width, \
              so `range_start + rotated` stays at or below u16::MAX; `offset` is likewise reduced \
              modulo that width before the narrowing"
)]
pub fn ephemeral_source_port(base: u16, offset: u64) -> u16 {
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
    let direct_match = request
        .iter()
        .filter_map(|layer| registry.matcher(layer.protocol_id().as_str()))
        .filter_map(|matcher| {
            let matched = matcher.matches(request, &response.packet)?;
            Some((matcher, matched))
        })
        .max_by_key(|(_, matched)| matched.confidence);
    if let Some((matcher, _)) = direct_match {
        let responder = matcher
            .responder(request, &response.packet)
            .unwrap_or(responder);
        let observation = match transport {
            Transport::Tcp => {
                let tcp = response
                    .packet
                    .iter()
                    .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Tcp))?;
                let flags = u16::try_from(tcp.field("flags")?.as_u64()?).ok()?;
                if flags & Tcp::RST != 0 {
                    Observation::new(responder, Correlation::TcpReset, "correlated TCP reset")
                } else if flags & (Tcp::SYN | Tcp::ACK) == (Tcp::SYN | Tcp::ACK) {
                    let request_tcp = request
                        .iter()
                        .find(|layer| BuiltinProtocol::of(*layer) == Some(BuiltinProtocol::Tcp))?;
                    let request_sequence =
                        u32::try_from(request_tcp.field("sequence")?.as_u64()?).ok()?;
                    let acknowledgment =
                        u32::try_from(tcp.field("acknowledgment")?.as_u64()?).ok()?;
                    if acknowledgment != request_sequence.wrapping_add(1) {
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
        Transport::Tcp => QuotedProbeTransport::Tcp,
        Transport::Udp => QuotedProbeTransport::Udp,
        Transport::Icmp => QuotedProbeTransport::Icmp,
    };
    let kind = quoted_icmp_error_kind(request, response, expected_transport)?;
    let icmp_protocol = response
        .iter()
        .find_map(|layer| match BuiltinProtocol::of(layer) {
            Some(protocol @ (BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6)) => Some(protocol),
            _ => None,
        })?;
    let ipv6 = icmp_protocol == BuiltinProtocol::Icmpv6;
    let (correlation, ipv4_reason, ipv6_reason) = match kind {
        QuotedIcmpError::PortUnreachable => (
            Correlation::PortUnreachable,
            "ICMPv4 port unreachable",
            "ICMPv6 port unreachable",
        ),
        QuotedIcmpError::AdministrativelyProhibited => (
            Correlation::AdministrativelyProhibited,
            "ICMPv4 administratively prohibited",
            "ICMPv6 policy or administrative rejection",
        ),
        QuotedIcmpError::DestinationUnreachable => (
            Correlation::DestinationUnreachable,
            "ICMPv4 destination unreachable",
            "ICMPv6 destination unreachable",
        ),
        QuotedIcmpError::TimeExceeded => (
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
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::{EPHEMERAL_SOURCE_PORT_BASE, ephemeral_source_port};

    /// Previous `scan_udp_source_port` and CLI `source_port` behaviour: an
    /// offset counted from the base wraps at the top of the dynamic range.
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

    /// Previous `dns_source_port` behaviour: a base inside the dynamic range
    /// rotates within that range and never leaves it.
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

    /// Previous `dns_source_port` behaviour: a base below the dynamic range
    /// rotates within `1..EPHEMERAL_SOURCE_PORT_BASE` instead, so a pinned low
    /// port never escapes into the dynamic range.
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
