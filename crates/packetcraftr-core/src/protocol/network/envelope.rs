// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded raw Ethernet/VLAN and IPv6 header walks and transport checksum coverage.
//! Walks report wire structure only; policies such as fragment placement and
//! whether authenticated traffic may be edited belong to their callers.

use std::net::IpAddr;

use crate::{
    codec::{LayerEncodeContext, NetworkEnvelope},
    layer::Layer,
    packet::semantics::ipv4_source_route_destination,
    protocol::BuiltinProtocol,
};

use crate::protocol::common::{invalid, network_from_addresses};

use super::{Ipv4, Ipv6, ip_protocol};

pub(super) fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    // AH participates in the IPv6 extension chain (RFC 8200), so the
    // pseudo-header scan for the final destination walks through it.
    BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ipv6_extension)
}

/// Extension headers whose wire encoding carries its own length, so a chain
/// walk can step over them: Hop-by-Hop (0), Routing (43), AH (51), and
/// Destination Options (60).
pub(crate) const fn is_walkable_ipv6_extension(next_header: u8) -> bool {
    matches!(
        next_header,
        ip_protocol::HOP_BY_HOP
            | ip_protocol::ROUTING
            | ip_protocol::AH
            | ip_protocol::DESTINATION_OPTIONS
    )
}

/// Wire length of one walkable extension header, from the protocol number
/// that selected it and its Hdr Ext Len byte. Hop-by-Hop, Routing, and
/// Destination Options count 8-byte units excluding the first; AH counts
/// 4-byte words minus two and can never be shorter than its 12 fixed bytes.
pub(crate) fn ipv6_extension_header_length(next_header: u8, encoded_length: u8) -> Option<usize> {
    match next_header {
        ip_protocol::HOP_BY_HOP | ip_protocol::ROUTING | ip_protocol::DESTINATION_OPTIONS => {
            usize::from(encoded_length)
                .checked_add(1)
                .and_then(|units| units.checked_mul(8))
        }
        ip_protocol::AH => usize::from(encoded_length)
            .checked_add(2)
            .and_then(|words| words.checked_mul(4))
            .filter(|length| *length >= 12),
        _ => None,
    }
}

/// Failure to walk a complete, finitely bounded raw header chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WalkError {
    #[error("truncated {0} header")]
    Truncated(&'static str),
    #[error("invalid {0} header length")]
    InvalidLength(&'static str),
    #[error("{header} depth exceeds {limit}")]
    DepthExceeded { header: &'static str, limit: usize },
}

/// The kind of a raw link header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkHeaderKind {
    Ethernet,
    Vlan8021Q,
    Vlan8021Ad,
}

/// An Ethernet or VLAN header, with offsets relative to the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkHeader {
    pub kind: LinkHeaderKind,
    pub offset: usize,
    pub length: usize,
    /// The VLAN tag's TCI; absent on the Ethernet header.
    pub tci: Option<u16>,
}

/// Validated Ethernet/VLAN chain. The depth bound counts VLAN tags, not Ethernet.
/// The iterator yields the Ethernet header followed by each tag in wire order.
pub struct EthernetWalk<'a> {
    bytes: &'a [u8],
    tags: usize,
    cursor: usize,
    payload_offset: usize,
    ether_type: u16,
}

impl<'a> EthernetWalk<'a> {
    pub fn new(bytes: &'a [u8], max_tags: usize) -> Result<Self, WalkError> {
        let kind = bytes.get(12..14).ok_or(WalkError::Truncated("Ethernet"))?;
        let mut ether_type = u16::from_be_bytes([kind[0], kind[1]]);
        let mut offset = 14_usize;
        let mut tags = 0;
        while matches!(ether_type, 0x8100 | 0x88a8) {
            if tags == max_tags {
                return Err(WalkError::DepthExceeded {
                    header: "VLAN",
                    limit: max_tags,
                });
            }
            let tag = bytes
                .get(offset..offset + 4)
                .ok_or(WalkError::Truncated("VLAN"))?;
            ether_type = u16::from_be_bytes([tag[2], tag[3]]);
            offset += 4;
            tags += 1;
        }
        Ok(Self {
            bytes,
            tags,
            cursor: 0,
            payload_offset: offset,
            ether_type,
        })
    }

    pub fn payload_offset(&self) -> usize {
        self.payload_offset
    }

    pub fn ether_type(&self) -> u16 {
        self.ether_type
    }
}

impl Iterator for EthernetWalk<'_> {
    type Item = LinkHeader;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.cursor;
        self.cursor += 1;
        if index == 0 {
            return Some(LinkHeader {
                kind: LinkHeaderKind::Ethernet,
                offset: 0,
                length: 14,
                tci: None,
            });
        }
        if index > self.tags {
            return None;
        }
        let offset = 14 + (index - 1) * 4;
        let kind = u16::from_be_bytes([self.bytes[offset - 2], self.bytes[offset - 1]]);
        Some(LinkHeader {
            kind: if kind == 0x88a8 {
                LinkHeaderKind::Vlan8021Ad
            } else {
                LinkHeaderKind::Vlan8021Q
            },
            offset,
            length: 4,
            tci: Some(u16::from_be_bytes([
                self.bytes[offset],
                self.bytes[offset + 1],
            ])),
        })
    }
}

/// Canonical raw IPv6 extension kinds that can be stepped over on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6HeaderKind {
    HopByHop,
    Routing,
    Fragment,
    Authentication,
    DestinationOptions,
}

impl Ipv6HeaderKind {
    fn from_number(number: u8) -> Option<Self> {
        Some(match number {
            ip_protocol::HOP_BY_HOP => Self::HopByHop,
            ip_protocol::ROUTING => Self::Routing,
            ip_protocol::FRAGMENT => Self::Fragment,
            ip_protocol::AH => Self::Authentication,
            ip_protocol::DESTINATION_OPTIONS => Self::DestinationOptions,
            _ => return None,
        })
    }
}

/// One IPv6 extension header. Offsets are relative to the supplied payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    pub kind: Ipv6HeaderKind,
    pub offset: usize,
    pub length: usize,
    pub next_header: u8,
}

/// Walks only IPv6 extensions, without imposing packet-edit or NDP policy.
/// The input is the *bounded IPv6 payload*, excluding the fixed 40-byte header.
/// Once `next_header` returns `None`, `upper_layer` identifies the remaining
/// protocol and offset within that payload. The bound counts extension headers.
pub struct Ipv6Walk<'a> {
    payload: &'a [u8],
    next: u8,
    offset: usize,
    depth: usize,
    max_depth: usize,
}

impl<'a> Ipv6Walk<'a> {
    pub fn new(payload: &'a [u8], next_header: u8, max_depth: usize) -> Self {
        Self {
            payload,
            next: next_header,
            offset: 0,
            depth: 0,
            max_depth,
        }
    }

    pub fn next_header(&mut self) -> Result<Option<Ipv6Header>, WalkError> {
        let Some(kind) = Ipv6HeaderKind::from_number(self.next) else {
            return Ok(None);
        };
        if self.depth == self.max_depth {
            return Err(WalkError::DepthExceeded {
                header: "IPv6 extensions",
                limit: self.max_depth,
            });
        }
        let header = self
            .payload
            .get(self.offset..)
            .and_then(|bytes| bytes.get(..2))
            .ok_or(WalkError::Truncated("IPv6 extension"))?;
        let length = if kind == Ipv6HeaderKind::Fragment {
            8
        } else {
            ipv6_extension_header_length(self.next, header[1])
                .ok_or(WalkError::InvalidLength("IPv6 extension"))?
        };
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WalkError::InvalidLength("IPv6 extension"))?;
        if end > self.payload.len() {
            return Err(WalkError::Truncated("IPv6 extension"));
        }
        let found = Ipv6Header {
            kind,
            offset: self.offset,
            length,
            next_header: header[0],
        };
        self.offset = end;
        self.next = header[0];
        self.depth += 1;
        Ok(Some(found))
    }

    pub fn upper_layer(&self) -> (u8, usize) {
        (self.next, self.offset)
    }
}

/// Raw IP headers for which a transport checksum is to be repaired.
/// IPv4 takes the complete header (including options); IPv6 takes the bounded
/// payload and the fixed header's Next Header value.
pub enum TransportEnvelope<'a> {
    Ipv4(&'a [u8]),
    Ipv6 {
        payload: &'a [u8],
        next_header: u8,
        max_extensions: usize,
    },
}

/// A packet shape whose transport checksum cannot be correctly reconstructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChecksumRefusal {
    #[error("transport checksum repair needs a complete datagram")]
    FragmentedDatagram,
    #[error("IPv4 source routing changes checksum destinations")]
    Ipv4SourceRoute,
    #[error("IPv6 routing header changes checksum destinations")]
    Ipv6RoutingHeader,
    #[error("IPv6 Home Address option changes checksum sources")]
    Ipv6HomeAddress,
    #[error("authenticated IPv6 header cannot be repaired")]
    AuthenticatedHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CoverageError {
    #[error(transparent)]
    Walk(#[from] WalkError),
    #[error(transparent)]
    Refused(#[from] ChecksumRefusal),
    #[error("{0}")]
    Invalid(&'static str),
}

/// Next protocol and offset of its first byte (relative to the IPv4 packet
/// or to the supplied IPv6 payload, respectively).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpperLayer {
    pub protocol: u8,
    pub offset: usize,
}

/// Refuses edits that would leave an unrepairable transport checksum. This
/// intentionally does not apply to link-only or network hop-limit/TTL edits.
pub fn transport_coverage(envelope: TransportEnvelope<'_>) -> Result<UpperLayer, CoverageError> {
    match envelope {
        TransportEnvelope::Ipv4(header) => {
            let Some(&first) = header.first() else {
                return Err(CoverageError::Invalid("truncated IPv4 header"));
            };
            let length = usize::from(first & 15) * 4;
            if first >> 4 != 4 || length < 20 || length != header.len() {
                return Err(CoverageError::Invalid("invalid IPv4 header length"));
            }
            let flags = u16::from_be_bytes([header[6], header[7]]);
            if flags & 0x3fff != 0 {
                return Err(ChecksumRefusal::FragmentedDatagram.into());
            }
            let mut option = 20;
            while option < length {
                match header[option] {
                    0 => break,
                    1 => option += 1,
                    131 | 137 => return Err(ChecksumRefusal::Ipv4SourceRoute.into()),
                    _ => {
                        let size = usize::from(
                            *header
                                .get(option + 1)
                                .ok_or(CoverageError::Invalid("truncated IPv4 option"))?,
                        );
                        if size < 2 || size > length - option {
                            return Err(CoverageError::Invalid("invalid IPv4 option length"));
                        }
                        option += size;
                    }
                }
            }
            Ok(UpperLayer {
                protocol: header[9],
                offset: length,
            })
        }
        TransportEnvelope::Ipv6 {
            payload,
            next_header,
            max_extensions,
        } => {
            let mut walk = Ipv6Walk::new(payload, next_header, max_extensions);
            while let Some(header) = walk.next_header()? {
                let bytes = &payload[header.offset..header.offset + header.length];
                match header.kind {
                    Ipv6HeaderKind::Routing => {
                        return Err(ChecksumRefusal::Ipv6RoutingHeader.into());
                    }
                    Ipv6HeaderKind::Fragment => {
                        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
                        if flags & 0xfff9 != 0 {
                            return Err(ChecksumRefusal::FragmentedDatagram.into());
                        }
                    }
                    Ipv6HeaderKind::Authentication => {
                        return Err(ChecksumRefusal::AuthenticatedHeader.into());
                    }
                    Ipv6HeaderKind::HopByHop | Ipv6HeaderKind::DestinationOptions => {
                        let mut option = 2;
                        while option < bytes.len() {
                            match bytes[option] {
                                0 => option += 1,
                                201 => return Err(ChecksumRefusal::Ipv6HomeAddress.into()),
                                _ => {
                                    let size =
                                        usize::from(*bytes.get(option + 1).ok_or(
                                            CoverageError::Invalid("truncated IPv6 option"),
                                        )?) + 2;
                                    if size > bytes.len() - option {
                                        return Err(CoverageError::Invalid(
                                            "invalid IPv6 option length",
                                        ));
                                    }
                                    option += size;
                                }
                            }
                        }
                    }
                }
            }
            let (protocol, offset) = walk.upper_layer();
            Ok(UpperLayer { protocol, offset })
        }
    }
}

/// Network addresses and upper-layer protocol of a pseudo-header checksum.
/// Call `checksum` with the checksum field already zeroed. For IPv4 UDP, a
/// previously disabled zero stays disabled; a *computed* zero is sent as 0xffff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PseudoHeader {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
}

impl PseudoHeader {
    pub fn checksum(
        self,
        name: &'static str,
        segment: &[u8],
        previous_checksum: u16,
    ) -> Result<Option<u16>, crate::codec::Error> {
        if self.source.is_ipv4() != self.destination.is_ipv4() {
            return Err(invalid(name, "mixed IP versions in pseudo-header"));
        }
        if self.source.is_ipv4() && segment.len() > usize::from(u16::MAX) {
            return Err(invalid(name, "IPv4 segment exceeds 65535 bytes"));
        }
        if self.protocol == ip_protocol::UDP
            && matches!(self.source, IpAddr::V4(_))
            && previous_checksum == 0
        {
            return Ok(None);
        }
        let value = crate::protocol::common::transport_checksum(
            name,
            network_from_addresses(self.source, self.destination),
            self.protocol,
            segment,
        )?;
        Ok(Some(if self.protocol == ip_protocol::UDP && value == 0 {
            0xffff
        } else {
            value
        }))
    }
}

/// `name` is the calling codec's protocol, so a missing or mismatched
/// envelope is reported against a protocol the catalog actually has.
pub(crate) fn resolve_envelope(
    name: &'static str,
    context: &LayerEncodeContext<'_>,
) -> Result<NetworkEnvelope, crate::codec::Error> {
    for index in (0..context.index).rev() {
        let Some(layer) = context.packet.layer(index) else {
            continue;
        };
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            let inherit_source = inherit_context && ipv4.source.is_unspecified();
            let inherit_destination = inherit_context && ipv4.destination.is_unspecified();
            let source = match context.build_context.source {
                Some(IpAddr::V4(source)) if inherit_source => source,
                _ => ipv4.source,
            };
            let destination = match context.build_context.destination {
                Some(IpAddr::V4(destination)) if inherit_destination => destination,
                _ => ipv4.destination,
            };
            let pseudo_header_destination =
                ipv4_source_route_destination(destination, &ipv4.options)
                    .map_err(|error| invalid(BuiltinProtocol::Ipv4.as_str(), error.to_string()))?;
            return Ok(network_from_addresses(
                source.into(),
                pseudo_header_destination.into(),
            ));
        }
        if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            let inherit_source = inherit_context && ipv6.source.is_unspecified();
            let inherit_destination = inherit_context && ipv6.destination.is_unspecified();
            // Only routing headers inside the nearest IPv6 envelope can
            // replace its pseudo-header destination. An SRH belonging to an
            // outer tunnel must not affect an encapsulated transport.
            let segment_routing_destination = (index.saturating_add(1)..context.index)
                .filter_map(|candidate_index| context.packet.layer(candidate_index))
                .take_while(|candidate| is_ipv6_extension_layer(*candidate))
                .filter_map(|candidate| {
                    candidate
                        .as_any()
                        .downcast_ref::<crate::protocol::ipv6::SegmentRoutingHeader>()?
                        .segments
                        .last()
                        .copied()
                })
                .last();
            let source = match context.build_context.source {
                Some(IpAddr::V6(source)) if inherit_source => source,
                _ => ipv6.source,
            };
            let destination = match context.build_context.destination {
                Some(IpAddr::V6(destination)) if inherit_destination => destination,
                _ => ipv6.destination,
            };
            return Ok(network_from_addresses(
                source.into(),
                segment_routing_destination.unwrap_or(destination).into(),
            ));
        }
    }
    match (
        context.build_context.source,
        context.build_context.destination,
    ) {
        (Some(source), Some(destination)) if source.is_ipv4() == destination.is_ipv4() => {
            Ok(NetworkEnvelope {
                source,
                destination,
            })
        }
        _ => Err(invalid(
            name,
            "the transport checksum requires matching source and destination IP addresses",
        )),
    }
}

pub(super) fn is_outer_network_layer(packet: &crate::packet::Packet, index: usize) -> bool {
    !packet
        .iter()
        .take(index)
        .any(|layer| BuiltinProtocol::of(layer).is_some_and(BuiltinProtocol::is_ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ethernet_vlan_walk_reports_wire_offsets_and_checks_depth_and_truncation() {
        let mut frame = vec![0_u8; 22];
        frame[12..14].copy_from_slice(&0x88a8_u16.to_be_bytes());
        frame[14..18].copy_from_slice(&[0xb0, 0x07, 0x81, 0x00]);
        frame[18..22].copy_from_slice(&[0x20, 0x08, 0x86, 0xdd]);
        let walk = EthernetWalk::new(&frame, 2).unwrap();
        assert_eq!((walk.payload_offset(), walk.ether_type()), (22, 0x86dd));
        assert_eq!(
            walk.collect::<Vec<_>>(),
            vec![
                LinkHeader {
                    kind: LinkHeaderKind::Ethernet,
                    offset: 0,
                    length: 14,
                    tci: None
                },
                LinkHeader {
                    kind: LinkHeaderKind::Vlan8021Ad,
                    offset: 14,
                    length: 4,
                    tci: Some(0xb007)
                },
                LinkHeader {
                    kind: LinkHeaderKind::Vlan8021Q,
                    offset: 18,
                    length: 4,
                    tci: Some(0x2008)
                },
            ]
        );
        assert!(matches!(
            EthernetWalk::new(&frame, 1),
            Err(WalkError::DepthExceeded { limit: 1, .. })
        ));
        for (size, name) in [(13, "Ethernet"), (17, "VLAN"), (21, "VLAN")] {
            assert!(
                matches!(EthernetWalk::new(&frame[..size], 2), Err(WalkError::Truncated(found)) if found == name)
            );
        }
        let mut untagged = frame[..14].to_vec();
        untagged[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        assert_eq!(EthernetWalk::new(&untagged, 0).unwrap().count(), 1);
    }

    #[test]
    fn ipv6_walk_covers_each_canonical_kind_and_bounds_each_wire_length() {
        for (number, kind, size, encoded) in [
            (0, Ipv6HeaderKind::HopByHop, 8, 0),
            (43, Ipv6HeaderKind::Routing, 16, 1),
            (44, Ipv6HeaderKind::Fragment, 8, 0xff),
            (51, Ipv6HeaderKind::Authentication, 12, 1),
            (60, Ipv6HeaderKind::DestinationOptions, 8, 0),
        ] {
            let mut payload = vec![0_u8; size + 1];
            payload[0] = 17;
            payload[1] = encoded;
            let mut walk = Ipv6Walk::new(&payload, number, 1);
            assert_eq!(
                walk.next_header().unwrap(),
                Some(Ipv6Header {
                    kind,
                    offset: 0,
                    length: size,
                    next_header: 17
                })
            );
            assert_eq!(walk.next_header().unwrap(), None);
            assert_eq!(walk.upper_layer(), (17, size));
            assert!(matches!(
                Ipv6Walk::new(&payload, number, 0).next_header(),
                Err(WalkError::DepthExceeded { limit: 0, .. })
            ));
            assert!(matches!(
                Ipv6Walk::new(&payload[..size - 1], number, 1).next_header(),
                Err(WalkError::Truncated("IPv6 extension"))
            ));
        }
        let payload = [60, 0, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0];
        let mut walk = Ipv6Walk::new(&payload, 0, 2);
        assert_eq!(walk.next_header().unwrap().unwrap().offset, 0);
        assert_eq!(walk.next_header().unwrap().unwrap().offset, 8);
        assert_eq!(walk.upper_layer(), (17, 16));
        let mut limited = Ipv6Walk::new(&payload, 0, 1);
        limited.next_header().unwrap();
        assert!(matches!(
            limited.next_header(),
            Err(WalkError::DepthExceeded { limit: 1, .. })
        ));
        assert!(matches!(
            Ipv6Walk::new(&[17], 0, 1).next_header(),
            Err(WalkError::Truncated("IPv6 extension"))
        ));
    }

    #[test]
    fn transport_coverage_refusals_and_atomic_fragment_are_typed() {
        let mut ipv4 = [0_u8; 24];
        ipv4[0] = 0x46;
        ipv4[9] = 17;
        for (kind, refusal) in [
            (131, ChecksumRefusal::Ipv4SourceRoute),
            (137, ChecksumRefusal::Ipv4SourceRoute),
        ] {
            ipv4[20] = kind;
            assert_eq!(
                transport_coverage(TransportEnvelope::Ipv4(&ipv4)),
                Err(CoverageError::Refused(refusal))
            );
        }
        ipv4[20] = 0;
        for flags in [0x2000_u16, 0x0001] {
            ipv4[6..8].copy_from_slice(&flags.to_be_bytes());
            assert_eq!(
                transport_coverage(TransportEnvelope::Ipv4(&ipv4)),
                Err(CoverageError::Refused(ChecksumRefusal::FragmentedDatagram))
            );
        }
        ipv4[6..8].fill(0);
        assert_eq!(
            transport_coverage(TransportEnvelope::Ipv4(&ipv4))
                .unwrap()
                .offset,
            24
        );
        ipv4[20..22].copy_from_slice(&[7, 5]);
        assert_eq!(
            transport_coverage(TransportEnvelope::Ipv4(&ipv4)),
            Err(CoverageError::Invalid("invalid IPv4 option length"))
        );

        for (number, header, refusal) in [
            (
                43,
                [17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ChecksumRefusal::Ipv6RoutingHeader,
            ),
            (
                44,
                [17, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                ChecksumRefusal::FragmentedDatagram,
            ),
            (
                0,
                [17, 0, 201, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ChecksumRefusal::Ipv6HomeAddress,
            ),
            (
                60,
                [17, 0, 201, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ChecksumRefusal::Ipv6HomeAddress,
            ),
            (
                51,
                [17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ChecksumRefusal::AuthenticatedHeader,
            ),
        ] {
            assert_eq!(
                transport_coverage(TransportEnvelope::Ipv6 {
                    payload: &header,
                    next_header: number,
                    max_extensions: 1
                }),
                Err(CoverageError::Refused(refusal))
            );
        }
        let atomic = [17, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            transport_coverage(TransportEnvelope::Ipv6 {
                payload: &atomic,
                next_header: 44,
                max_extensions: 1
            })
            .unwrap(),
            UpperLayer {
                protocol: 17,
                offset: 8
            }
        );
        let invalid_option = [17, 0, 1, 7, 0, 0, 0, 0];
        assert_eq!(
            transport_coverage(TransportEnvelope::Ipv6 {
                payload: &invalid_option,
                next_header: 60,
                max_extensions: 1
            }),
            Err(CoverageError::Invalid("invalid IPv6 option length"))
        );
    }

    #[test]
    fn pseudo_header_vectors_and_udp_zero_semantics() {
        let v4 = PseudoHeader {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            protocol: 17,
        };
        let mut udp = [0, 1, 0, 2, 0, 8, 0, 0];
        assert_eq!(v4.checksum("udp", &udp, 1).unwrap(), Some(0x13a4));
        assert_eq!(v4.checksum("udp", &udp, 0).unwrap(), None);
        udp[..2].copy_from_slice(&0x13a5_u16.to_be_bytes());
        assert_eq!(v4.checksum("udp", &udp, 1).unwrap(), Some(0xffff));

        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination: Ipv6Addr = "ff02::1:ff00:abcd".parse().unwrap();
        let mut solicitation = [0_u8; 32];
        solicitation[0] = 135;
        solicitation[8..24]
            .copy_from_slice(&"2001:db8::abcd".parse::<Ipv6Addr>().unwrap().octets());
        solicitation[24..].copy_from_slice(&[1, 1, 2, 0, 0, 0, 0, 1]);
        let v6 = PseudoHeader {
            source: source.into(),
            destination: destination.into(),
            protocol: 58,
        };
        assert_eq!(
            v6.checksum("icmpv6", &solicitation, 0).unwrap(),
            Some(0xc48f)
        );
        solicitation[2..4].copy_from_slice(&0xc48f_u16.to_be_bytes());
        assert_eq!(v6.checksum("icmpv6", &solicitation, 0).unwrap(), Some(0));
    }
}
