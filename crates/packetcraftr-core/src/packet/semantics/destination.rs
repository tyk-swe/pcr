// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use super::error::Error;
use super::path::{DESTINATION, IpFamily, SEGMENTS, TARGET_PROTOCOL, ip_path_at};
use crate::field::FieldValue;
use crate::layer::Malformed;
use crate::packet::Packet;
use crate::protocol::BuiltinProtocol;

pub(super) const ROUTE_FIELDS: [&str; 3] = [DESTINATION, SEGMENTS, TARGET_PROTOCOL];

/// Enumerates every address that can affect a live destination. Unknown
/// protocols cannot opt into route semantics by imitating reflective names.
pub fn live_destinations(packet: &Packet) -> Result<Vec<IpAddr>, Error> {
    let mut destinations = Vec::new();
    for (index, layer) in packet.iter().enumerate() {
        if let Some(malformed) = layer.as_any().downcast_ref::<Malformed>()
            && let Some(intended) = malformed.intended_protocol.as_deref()
            && BuiltinProtocol::from_name_or_alias(intended)
                .is_some_and(malformed_protocol_may_hide_destination)
        {
            return Err(Error::MalformedMayHideDestination {
                protocol: intended.to_owned(),
                reason: malformed.reason.clone(),
            });
        }
        match BuiltinProtocol::of(layer) {
            Some(protocol @ (BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6)) => {
                let family = if protocol == BuiltinProtocol::Ipv4 {
                    IpFamily::V4
                } else {
                    IpFamily::V6
                };
                let path = ip_path_at(packet, index, packet.len(), family)?;
                push_if_specified(&mut destinations, path.header_destination);
                for destination in path.declared_route_destinations {
                    push_if_specified(&mut destinations, destination);
                }
            }
            Some(BuiltinProtocol::Ipv6Srh) => {
                validate_attached_srh(packet, index)?;
            }
            Some(BuiltinProtocol::Arp) => match layer.field(TARGET_PROTOCOL) {
                Some(FieldValue::Ipv4(value)) => {
                    push_if_specified(&mut destinations, IpAddr::V4(value));
                }
                Some(_) => {
                    return Err(Error::field(
                        layer.protocol_id(),
                        TARGET_PROTOCOL,
                        "is not IPv4",
                    ));
                }
                None => {
                    return Err(Error::field(
                        layer.protocol_id(),
                        TARGET_PROTOCOL,
                        "is missing",
                    ));
                }
            },
            Some(_) => {}
            None => {
                if let Some(field) = ROUTE_FIELDS.iter().find(|field| {
                    layer
                        .schema()
                        .fields
                        .iter()
                        .any(|schema| schema.name == **field)
                        || layer.field(field).is_some()
                }) {
                    return Err(Error::UnknownProtocolRouteField {
                        protocol: *layer.protocol_id(),
                        field,
                    });
                }
            }
        }
    }
    Ok(destinations)
}

// Keep this match exhaustive so every newly added built-in protocol must make
// an explicit live-authorization decision.
fn malformed_protocol_may_hide_destination(protocol: BuiltinProtocol) -> bool {
    match protocol {
        BuiltinProtocol::Ah
        | BuiltinProtocol::Arp
        | BuiltinProtocol::BsdLoop
        | BuiltinProtocol::BsdNull
        | BuiltinProtocol::Erspan
        | BuiltinProtocol::Ethernet
        | BuiltinProtocol::Geneve
        | BuiltinProtocol::Gre
        | BuiltinProtocol::Ipv4
        | BuiltinProtocol::Ipv6
        | BuiltinProtocol::Ipv6DestinationOptions
        | BuiltinProtocol::Ipv6Fragment
        | BuiltinProtocol::Ipv6HopByHop
        | BuiltinProtocol::Ipv6Srh
        | BuiltinProtocol::L2tpv3
        | BuiltinProtocol::LinuxSll
        | BuiltinProtocol::LinuxSll2
        | BuiltinProtocol::Llc
        | BuiltinProtocol::Mpls
        | BuiltinProtocol::Ppp
        | BuiltinProtocol::Pppoe
        | BuiltinProtocol::RawIp
        | BuiltinProtocol::Snap
        | BuiltinProtocol::Udp
        | BuiltinProtocol::Vlan
        | BuiltinProtocol::Vlan8021ad
        | BuiltinProtocol::Vxlan => true,
        BuiltinProtocol::Dns
        | BuiltinProtocol::Esp
        | BuiltinProtocol::Icmpv4
        | BuiltinProtocol::Icmpv6
        | BuiltinProtocol::Igmp
        | BuiltinProtocol::Malformed
        | BuiltinProtocol::Padding
        | BuiltinProtocol::Raw
        | BuiltinProtocol::Sctp
        | BuiltinProtocol::Tcp
        | BuiltinProtocol::Tls => false,
    }
}

fn validate_attached_srh(packet: &Packet, srh_index: usize) -> Result<(), Error> {
    for (network_index, candidate) in packet.iter().enumerate().take(srh_index).rev() {
        match BuiltinProtocol::of(candidate) {
            Some(BuiltinProtocol::Ipv6) => {
                ip_path_at(
                    packet,
                    network_index,
                    srh_index.saturating_add(1),
                    IpFamily::V6,
                )?;
                return Ok(());
            }
            Some(protocol) if protocol.is_ipv6_extension() => {}
            _ => break,
        }
    }
    Err(Error::DetachedSegmentRoutingHeader)
}

fn push_if_specified(destinations: &mut Vec<IpAddr>, destination: IpAddr) {
    if !destination.is_unspecified() && !destinations.contains(&destination) {
        destinations.push(destination);
    }
}
