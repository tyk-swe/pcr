// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Necessary response identities for candidate discovery, never attribution.
//!
//! Keys retain the original transmission's address/port orientation. A direct
//! reply reverses those operands; an ICMP error contributes its validated quoted
//! operands. Full matchers still establish integrity, scope, tokens and shape.

use std::net::IpAddr;

use super::{
    BuiltinProtocol,
    network::{Icmpv4, Icmpv6, Ipv4, Ipv6, ip_protocol},
    semantics,
};
use crate::{
    field::{self, WireValue},
    packet::Packet,
};

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
        if let Some(key) = semantics::transport_key(layer) {
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
        if let Some(icmp) = layer.downcast_ref::<Icmpv4>() {
            return Some(Identity::Icmp {
                source,
                destination,
                protocol: ip_protocol::ICMPV4,
                identity: icmp.body.get(..4)?.try_into().ok()?,
            });
        }
        if let Some(icmp) = layer.downcast_ref::<Icmpv6>() {
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
        if let Some(ip) = layer.downcast_ref::<Ipv4>() {
            match ip.protocol {
                WireValue::Exact(protocol) => Some(protocol),
                _ => None,
            }
        } else if let Some(ip) = layer.downcast_ref::<Ipv6>() {
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
    if first.is::<Ipv6>() {
        for layer in layers.take_while(|layer| {
            BuiltinProtocol::of(*layer).is_some_and(BuiltinProtocol::is_ipv6_extension)
        }) {
            if protocols.len() > super::headers::MAX_IPV6_EXTENSIONS {
                return None;
            }
            if let Some(field::Value::Unsigned(protocol)) = layer.field("next_header") {
                protocols.push(u8::try_from(protocol).ok()?);
            }
        }
    }
    Some(protocols)
}
