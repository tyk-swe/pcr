// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one identity extraction for decoded packets: transport keys, necessary
//! response identities for candidate discovery (never attribution), and
//! encapsulation identifiers. Downcasts that read identity belong here.
//!
//! Keys retain the original transmission's address/port orientation. A direct
//! reply reverses those operands; an ICMP error contributes its validated quoted
//! operands. Full matchers still establish integrity, scope, tokens and shape.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::{
    BuiltinProtocol,
    application::dns::{Dns, Question},
    link::{Arp, Ethernet, Vlan, Vlan8021ad},
    network::{Fragment, Icmpv4, Icmpv6, Ipv4, Ipv6, SegmentRoutingHeader, ip_protocol},
    semantics,
    transport::{Sctp, Tcp, TcpOption, Udp},
    tunnel::{Ah, Erspan, Geneve, Gre, L2tpv3, Mpls, Pppoe, Vxlan},
};
use crate::{
    field::{self, WireValue},
    layer::Layer,
    packet::{Packet, VlanKind, VlanTag},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportKey {
    pub protocol: BuiltinProtocol,
    pub source_port: u16,
    pub destination_port: u16,
}

/// Extracts the transport tuple of a built-in TCP, UDP, or SCTP layer.
pub fn transport_key(layer: &dyn Layer) -> Option<TransportKey> {
    let (protocol, source_port, destination_port) = if let Some(tcp) = cast::<Tcp>(layer) {
        (BuiltinProtocol::Tcp, tcp.source_port, tcp.destination_port)
    } else if let Some(udp) = cast::<Udp>(layer) {
        (BuiltinProtocol::Udp, udp.source_port, udp.destination_port)
    } else {
        let sctp = cast::<Sctp>(layer)?;
        (
            BuiltinProtocol::Sctp,
            sctp.source_port,
            sctp.destination_port,
        )
    };
    Some(TransportKey {
        protocol,
        source_port,
        destination_port,
    })
}

pub fn transport_keys_are_reversed(request: &dyn Layer, response: &dyn Layer) -> bool {
    let (Some(request), Some(response)) = (transport_key(request), transport_key(response)) else {
        return false;
    };
    request.protocol == response.protocol
        && request.source_port == response.destination_port
        && request.destination_port == response.source_port
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TunnelId {
    Vlan {
        vlan_id: u16,
    },
    Vlan8021ad {
        vlan_id: u16,
    },
    Vxlan {
        vni: u32,
    },
    Geneve {
        vni: u32,
    },
    Gre {
        key: Option<u32>,
    },
    Mpls {
        label: u32,
    },
    Pppoe {
        session_id: u16,
        endpoints: Option<([u8; 6], [u8; 6])>,
    },
    L2tpv3 {
        session_id: u32,
    },
    Erspan {
        vlan: u16,
        session_id: u16,
    },
    Ah {
        spi: u32,
    },
}

pub fn tunnel_identifier(
    layer: &dyn Layer,
    ethernet: Option<([u8; 6], [u8; 6])>,
) -> Option<TunnelId> {
    if let Some(vlan) = cast::<Vlan>(layer) {
        Some(TunnelId::Vlan {
            vlan_id: vlan.vlan_id,
        })
    } else if let Some(vlan) = cast::<Vlan8021ad>(layer) {
        Some(TunnelId::Vlan8021ad {
            vlan_id: vlan.vlan_id,
        })
    } else if let Some(vxlan) = cast::<Vxlan>(layer) {
        Some(TunnelId::Vxlan { vni: vxlan.vni })
    } else if let Some(geneve) = cast::<Geneve>(layer) {
        Some(TunnelId::Geneve { vni: geneve.vni })
    } else if let Some(gre) = cast::<Gre>(layer) {
        Some(TunnelId::Gre { key: gre.key })
    } else if let Some(mpls) = cast::<Mpls>(layer) {
        Some(TunnelId::Mpls { label: mpls.label })
    } else if let Some(pppoe) = cast::<Pppoe>(layer) {
        Some(TunnelId::Pppoe {
            session_id: pppoe.session_id,
            endpoints: ethernet,
        })
    } else if let Some(l2tp) = cast::<L2tpv3>(layer) {
        Some(TunnelId::L2tpv3 {
            session_id: l2tp.session_id,
        })
    } else if let Some(erspan) = cast::<Erspan>(layer) {
        Some(TunnelId::Erspan {
            vlan: erspan.vlan,
            session_id: erspan.session_id,
        })
    } else {
        cast::<Ah>(layer).map(|ah| TunnelId::Ah { spi: ah.spi })
    }
}

fn next_header(layer: &dyn Layer) -> Option<u8> {
    let index = layer.schema().field_index("next_header")?;
    match layer.field_by_index(index) {
        Some(field::Value::Unsigned(value)) => u8::try_from(value).ok(),
        _ => None,
    }
}

pub fn outer_has_protocol(packet: &Packet, protocol: u8) -> bool {
    let mut layers = semantics::outer_layers(packet)
        .skip_while(|layer| !BuiltinProtocol::of(*layer).is_some_and(BuiltinProtocol::is_ip));
    let Some(header) = layers.next() else {
        return false;
    };
    if let Some(ipv4) = cast::<Ipv4>(header) {
        return ipv4.protocol == WireValue::Exact(protocol);
    }
    cast::<Ipv6>(header).is_some_and(|ipv6| ipv6.next_header == WireValue::Exact(protocol))
        || layers
            .take_while(|layer| {
                BuiltinProtocol::of(*layer).is_some_and(BuiltinProtocol::is_ipv6_extension)
            })
            .any(|layer| next_header(layer) == Some(protocol))
}

/// Maximum temporary keys extracted from one response. Longer supported shapes
/// use conservative lookup instead of silently dropping possible contributors.
pub const MAX_RESPONSE_IDENTITIES: usize = super::headers::MAX_IPV6_EXTENSIONS + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Identity {
    Transport {
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        source_port: u16,
        destination_port: u16,
    },
    Icmp {
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        identity: [u8; 4],
    },
    IpProtocol {
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
    },
}

impl Identity {
    pub(in crate::protocol) fn transport(
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        payload: &[u8],
    ) -> Option<Self> {
        match protocol {
            ip_protocol::TCP | ip_protocol::UDP | ip_protocol::SCTP => {
                let bytes = payload.first_chunk::<4>()?;
                Some(Self::Transport {
                    source,
                    destination,
                    protocol,
                    source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
                    destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
                })
            }
            ip_protocol::ICMPV4 | ip_protocol::ICMPV6 => Some(Self::Icmp {
                source,
                destination,
                protocol,
                identity: payload.get(4..8)?.try_into().ok()?,
            }),
            _ => None,
        }
    }

    fn reversed(self) -> Self {
        match self {
            Self::Transport {
                source,
                destination,
                protocol,
                source_port,
                destination_port,
            } => Self::Transport {
                source: destination,
                destination: source,
                protocol,
                source_port: destination_port,
                destination_port: source_port,
            },
            Self::Icmp {
                source,
                destination,
                protocol,
                identity,
            } => Self::Icmp {
                source: destination,
                destination: source,
                protocol,
                identity,
            },
            Self::IpProtocol {
                source,
                destination,
                protocol,
            } => Self::IpProtocol {
                source: destination,
                destination: source,
                protocol,
            },
        }
    }

    fn with_destination(self, destination: IpAddr) -> Self {
        match self {
            Self::Transport {
                source,
                protocol,
                source_port,
                destination_port,
                ..
            } => Self::Transport {
                source,
                destination,
                protocol,
                source_port,
                destination_port,
            },
            Self::Icmp {
                source,
                protocol,
                identity,
                ..
            } => Self::Icmp {
                source,
                destination,
                protocol,
                identity,
            },
            Self::IpProtocol {
                source, protocol, ..
            } => Self::IpProtocol {
                source,
                destination,
                protocol,
            },
        }
    }
}

/// Direct and quoted keys for one request. They can coincide. `None` requires
/// conservative discovery; notably an unrecognized outer tunnel is never guessed.
pub fn request(packet: &Packet) -> Option<[Identity; 2]> {
    let path = semantics::outer_ip_path(packet).ok()??;
    let direct = outer_transport(packet, path.source, path.final_destination).or_else(|| {
        if !packet.iter().all(|layer| {
            matches!(
                BuiltinProtocol::of(layer),
                Some(
                    BuiltinProtocol::Ethernet
                        | BuiltinProtocol::Ipv4
                        | BuiltinProtocol::Ipv6
                        | BuiltinProtocol::Padding
                )
            )
        }) {
            return None;
        }
        outer_protocol(packet).map(|protocol| Identity::IpProtocol {
            source: path.source,
            destination: path.final_destination,
            protocol,
        })
    })?;
    Some([direct, direct.with_destination(path.header_destination)])
}

/// Necessary keys of a decoded response, preserving all direct/quoted candidate
/// families. `None` requires conservative discovery. An empty list means there
/// is no usable outer IP path, which the authoritative matcher also requires.
pub fn response(packet: &Packet) -> Option<Vec<Identity>> {
    let path = match semantics::outer_ip_path(packet) {
        Ok(Some(path)) => path,
        Ok(None) | Err(_) => return Some(Vec::new()),
    };
    let mut keys = Vec::new();
    if let Some(transport) = outer_transport(packet, path.source, path.final_destination) {
        keys.push(transport.reversed());
    }
    for protocol in outer_protocols(packet)? {
        keys.push(Identity::IpProtocol {
            source: path.final_destination,
            destination: path.source,
            protocol,
        });
    }
    if let Some((protocol, transport)) = super::matcher::quoted_identity(packet) {
        keys.push(protocol);
        keys.extend(transport);
    }
    keys.sort_unstable();
    keys.dedup();
    if keys.is_empty() {
        None
    } else {
        (keys.len() <= MAX_RESPONSE_IDENTITIES).then_some(keys)
    }
}

fn outer_transport(packet: &Packet, source: IpAddr, destination: IpAddr) -> Option<Identity> {
    for layer in semantics::outer_layers(packet) {
        if let Some(key) = transport_key(layer) {
            let protocol = match key.protocol {
                BuiltinProtocol::Tcp => ip_protocol::TCP,
                BuiltinProtocol::Udp => ip_protocol::UDP,
                BuiltinProtocol::Sctp => ip_protocol::SCTP,
                _ => return None,
            };
            return Some(Identity::Transport {
                source,
                destination,
                protocol,
                source_port: key.source_port,
                destination_port: key.destination_port,
            });
        }
        if let Some(icmp) = cast::<Icmpv4>(layer) {
            return Some(Identity::Icmp {
                source,
                destination,
                protocol: ip_protocol::ICMPV4,
                identity: icmp.body.get(..4)?.try_into().ok()?,
            });
        }
        if let Some(icmp) = cast::<Icmpv6>(layer) {
            return Some(Identity::Icmp {
                source,
                destination,
                protocol: ip_protocol::ICMPV6,
                identity: icmp.body.get(..4)?.try_into().ok()?,
            });
        }
    }
    None
}

fn outer_protocol(packet: &Packet) -> Option<u8> {
    semantics::outer_layers(packet).find_map(|layer| {
        if let Some(ip) = cast::<Ipv4>(layer) {
            match ip.protocol {
                WireValue::Exact(protocol) => Some(protocol),
                _ => None,
            }
        } else if let Some(ip) = cast::<Ipv6>(layer) {
            match ip.next_header {
                WireValue::Exact(protocol) => Some(protocol),
                _ => None,
            }
        } else {
            None
        }
    })
}

fn outer_protocols(packet: &Packet) -> Option<Vec<u8>> {
    let mut layers = semantics::outer_layers(packet)
        .skip_while(|layer| !BuiltinProtocol::of(*layer).is_some_and(BuiltinProtocol::is_ip));
    let first = layers.next()?;
    let mut protocols = outer_protocol(packet).into_iter().collect::<Vec<_>>();
    if BuiltinProtocol::Ipv6.identifies(first) {
        for layer in layers.take_while(|layer| {
            BuiltinProtocol::of(*layer).is_some_and(BuiltinProtocol::is_ipv6_extension)
        }) {
            if protocols.len() > super::headers::MAX_IPV6_EXTENSIONS {
                return None;
            }
            if let Some(index) = layer.schema().field_index("next_header")
                && let Some(field::Value::Unsigned(protocol)) = layer.field_by_index(index)
            {
                protocols.push(u8::try_from(protocol).ok()?);
            }
        }
    }
    Some(protocols)
}

fn cast<T: Layer>(layer: &dyn Layer) -> Option<&T> {
    layer.downcast_ref()
}

fn cast_mut<T: Layer>(layer: &mut dyn Layer) -> Option<&mut T> {
    layer.downcast_mut()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkHeader {
    V4 {
        source: Ipv4Addr,
        destination: Ipv4Addr,
        identification: u16,
        fragment_offset: u16,
        more_fragments: bool,
        total_length: WireValue<u16>,
        protocol: WireValue<u8>,
        ttl: u8,
        options: Bytes,
    },
    V6 {
        source: Ipv6Addr,
        destination: Ipv6Addr,
        payload_length: WireValue<u16>,
        next_header: WireValue<u8>,
        hop_limit: u8,
    },
}

impl NetworkHeader {
    pub fn endpoints(&self) -> (IpAddr, IpAddr) {
        match self {
            Self::V4 {
                source,
                destination,
                ..
            } => (IpAddr::V4(*source), IpAddr::V4(*destination)),
            Self::V6 {
                source,
                destination,
                ..
            } => (IpAddr::V6(*source), IpAddr::V6(*destination)),
        }
    }

    pub fn hop_limit(&self) -> u8 {
        match self {
            Self::V4 { ttl, .. } => *ttl,
            Self::V6 { hop_limit, .. } => *hop_limit,
        }
    }
}

pub fn network_header(layer: &dyn Layer) -> Option<NetworkHeader> {
    if let Some(ip) = cast::<Ipv4>(layer) {
        return Some(NetworkHeader::V4 {
            source: ip.source,
            destination: ip.destination,
            identification: ip.identification,
            fragment_offset: ip.fragment_offset,
            more_fragments: ip.more_fragments,
            total_length: ip.total_length.clone(),
            protocol: ip.protocol.clone(),
            ttl: ip.ttl,
            options: ip.options.clone(),
        });
    }
    cast::<Ipv6>(layer).map(|ip| NetworkHeader::V6 {
        source: ip.source,
        destination: ip.destination,
        payload_length: ip.payload_length.clone(),
        next_header: ip.next_header.clone(),
        hop_limit: ip.hop_limit,
    })
}

pub fn network_endpoints(layer: &dyn Layer) -> Option<(IpAddr, IpAddr)> {
    network_header(layer).map(|header| header.endpoints())
}

pub fn hop_limit(layer: &dyn Layer) -> Option<u8> {
    network_header(layer).map(|header| header.hop_limit())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FragmentHeader {
    pub identification: u32,
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub next_header: WireValue<u8>,
}

pub fn fragment_header(layer: &dyn Layer) -> Option<FragmentHeader> {
    cast::<Fragment>(layer).map(|fragment| FragmentHeader {
        identification: fragment.identification,
        fragment_offset: fragment.fragment_offset,
        more_fragments: fragment.more_fragments,
        next_header: fragment.next_header.clone(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRouting {
    pub segments: Vec<Ipv6Addr>,
    pub segments_left: WireValue<u8>,
    pub last_entry: WireValue<u8>,
    pub flags: u8,
}

pub fn segment_routing(layer: &dyn Layer) -> Option<SegmentRouting> {
    cast::<SegmentRoutingHeader>(layer).map(|srh| SegmentRouting {
        segments: srh.segments.clone(),
        segments_left: srh.segments_left.clone(),
        last_entry: srh.last_entry.clone(),
        flags: srh.flags,
    })
}

pub fn ether_type(layer: &dyn Layer) -> Option<WireValue<u16>> {
    if let Some(link) = cast::<Ethernet>(layer) {
        return Some(link.ether_type.clone());
    }
    if let Some(tag) = cast::<Vlan>(layer) {
        return Some(tag.ether_type.clone());
    }
    cast::<Vlan8021ad>(layer).map(|tag| tag.ether_type.clone())
}

pub fn link_addresses(layer: &dyn Layer) -> Option<([u8; 6], [u8; 6])> {
    cast::<Ethernet>(layer).map(|link| (link.source, link.destination))
}

pub fn vlan_tag(layer: &dyn Layer) -> Option<VlanTag> {
    if let Some(tag) = cast::<Vlan>(layer) {
        return Some(VlanTag {
            kind: VlanKind::Ieee8021Q,
            priority: tag.priority,
            drop_eligible: tag.drop_eligible,
            vlan_id: tag.vlan_id,
        });
    }
    cast::<Vlan8021ad>(layer).map(|tag| VlanTag {
        kind: VlanKind::Ieee8021Ad,
        priority: tag.priority,
        drop_eligible: tag.drop_eligible,
        vlan_id: tag.vlan_id,
    })
}

pub fn arp_target(layer: &dyn Layer) -> Option<Ipv4Addr> {
    cast::<Arp>(layer).map(|arp| arp.target_protocol)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpMessage<'a> {
    pub protocol: BuiltinProtocol,
    pub icmp_type: u8,
    pub code: u8,
    pub body: &'a Bytes,
}

pub fn icmp_message(layer: &dyn Layer) -> Option<IcmpMessage<'_>> {
    if let Some(icmp) = cast::<Icmpv4>(layer) {
        return Some(IcmpMessage {
            protocol: BuiltinProtocol::Icmpv4,
            icmp_type: icmp.icmp_type,
            code: icmp.code,
            body: &icmp.body,
        });
    }
    cast::<Icmpv6>(layer).map(|icmp| IcmpMessage {
        protocol: BuiltinProtocol::Icmpv6,
        icmp_type: icmp.icmp_type,
        code: icmp.code,
        body: &icmp.body,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpHeader<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u16,
    pub window: u16,
    pub options: &'a [TcpOption],
}

pub fn tcp_header(layer: &dyn Layer) -> Option<TcpHeader<'_>> {
    cast::<Tcp>(layer).map(|tcp| TcpHeader {
        source_port: tcp.source_port,
        destination_port: tcp.destination_port,
        sequence: tcp.sequence,
        acknowledgment: tcp.acknowledgment,
        flags: tcp.flags,
        window: tcp.window,
        options: &tcp.options,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: WireValue<u16>,
}

pub fn udp_header(layer: &dyn Layer) -> Option<UdpHeader> {
    cast::<Udp>(layer).map(|udp| UdpHeader {
        source_port: udp.source_port,
        destination_port: udp.destination_port,
        length: udp.length.clone(),
    })
}

pub fn udp_length(layer: &dyn Layer) -> Option<WireValue<u16>> {
    udp_header(layer).map(|udp| udp.length)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SctpHeader {
    pub verification_tag: u32,
    pub checksum: WireValue<u32>,
}

pub fn sctp_header(layer: &dyn Layer) -> Option<SctpHeader> {
    cast::<Sctp>(layer).map(|sctp| SctpHeader {
        verification_tag: sctp.verification_tag,
        checksum: sctp.checksum.clone(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsIdentity<'a> {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub questions: &'a [Question],
}

pub fn dns_identity(layer: &dyn Layer) -> Option<DnsIdentity<'_>> {
    cast::<Dns>(layer).map(|dns| DnsIdentity {
        id: dns.id,
        response: dns.response,
        opcode: dns.opcode,
        questions: &dns.questions,
    })
}

pub fn swap_link_addresses(layer: &mut dyn Layer) -> bool {
    let Some(link) = cast_mut::<Ethernet>(layer) else {
        return false;
    };
    std::mem::swap(&mut link.source, &mut link.destination);
    true
}

pub fn swap_network_addresses(layer: &mut dyn Layer) -> bool {
    if let Some(ip) = cast_mut::<Ipv4>(layer) {
        std::mem::swap(&mut ip.source, &mut ip.destination);
        return true;
    }
    let Some(ip) = cast_mut::<Ipv6>(layer) else {
        return false;
    };
    std::mem::swap(&mut ip.source, &mut ip.destination);
    true
}

pub fn reset_network_lengths(layer: &mut dyn Layer) {
    if let Some(ip) = cast_mut::<Ipv4>(layer) {
        ip.total_length = WireValue::Auto;
        ip.checksum = WireValue::Auto;
    } else if let Some(ip) = cast_mut::<Ipv6>(layer) {
        ip.payload_length = WireValue::Auto;
    }
}

pub fn set_network_addresses(layer: &mut dyn Layer, source: IpAddr, destination: IpAddr) -> bool {
    if let (Some(ip), IpAddr::V4(source), IpAddr::V4(destination)) =
        (cast_mut::<Ipv4>(layer), source, destination)
    {
        ip.source = source;
        ip.destination = destination;
        return true;
    }
    let (IpAddr::V6(source), IpAddr::V6(destination)) = (source, destination) else {
        return false;
    };
    let Some(ip) = cast_mut::<Ipv6>(layer) else {
        return false;
    };
    ip.source = source;
    ip.destination = destination;
    true
}

pub fn set_link_addresses(layer: &mut dyn Layer, source: [u8; 6], destination: [u8; 6]) -> bool {
    let Some(link) = cast_mut::<Ethernet>(layer) else {
        return false;
    };
    link.source = source;
    link.destination = destination;
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpMessage {
    pub operation: u16,
    pub sender_hardware: [u8; 6],
    pub sender_protocol: Ipv4Addr,
    pub target_hardware: [u8; 6],
    pub target_protocol: Ipv4Addr,
}

pub fn arp_message(layer: &dyn Layer) -> Option<ArpMessage> {
    cast::<Arp>(layer).map(|arp| ArpMessage {
        operation: arp.operation,
        sender_hardware: arp.sender_hardware,
        sender_protocol: arp.sender_protocol,
        target_hardware: arp.target_hardware,
        target_protocol: arp.target_protocol,
    })
}

pub fn dns_wire(layer: &dyn Layer) -> Option<&Bytes> {
    cast::<Dns>(layer).map(Dns::wire)
}

pub fn geneve_protocol_type(layer: &dyn Layer) -> Option<WireValue<u16>> {
    cast::<Geneve>(layer).map(|geneve| geneve.protocol_type.clone())
}
