// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use super::error::Error;
use super::path::{IpHeader, ip_path_at};
use crate::layer::Malformed;
use crate::packet::Packet;
use crate::protocol::BuiltinProtocol;
use crate::protocol::link::Arp;
use crate::protocol::network::Ipv6;

/// Field names that carry a route on a built-in layer. A layer of an unknown
/// protocol that declares or reflects one is refused rather than trusted.
const ROUTE_FIELDS: [&str; 3] = ["destination", "segments", "target_protocol"];

/// Enumerates every address that can determine where the packet is routed. Unknown
/// protocols cannot opt into route semantics by imitating reflective names.
pub fn live_destinations(packet: &Packet) -> Result<Vec<IpAddr>, Error> {
    let mut destinations = Vec::new();
    for (index, layer) in packet.iter().enumerate() {
        // Registries resolve protocol names trimmed and case-insensitively, so
        // a hand-built "IPv4" must not slip past the check "ipv4" meets.
        if let Some(malformed) = layer.downcast_ref::<Malformed>()
            && let Some(intended) = malformed.intended_protocol.as_deref()
            && BuiltinProtocol::from_name_or_alias(&intended.trim().to_ascii_lowercase())
                .is_some_and(malformed_protocol_may_hide_destination)
        {
            return Err(Error::MalformedMayHideDestination {
                protocol: intended.to_owned(),
                reason: malformed.reason.clone(),
            });
        }
        if let Some(header) = IpHeader::of(layer) {
            let path = ip_path_at(packet, index, packet.len(), header)?;
            push_if_specified(&mut destinations, path.header_destination);
            for destination in path.declared_route_destinations {
                push_if_specified(&mut destinations, destination);
            }
            continue;
        }
        if let Some(arp) = layer.downcast_ref::<Arp>() {
            push_if_specified(&mut destinations, IpAddr::V4(arp.target_protocol));
            continue;
        }
        match BuiltinProtocol::of(layer) {
            Some(BuiltinProtocol::Ipv6Srh) => {
                validate_attached_srh(packet, index)?;
            }
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
// an explicit decision about whether its malformed form can hide a destination.
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
        BuiltinProtocol::Dhcpv4
        | BuiltinProtocol::Dhcpv6
        | BuiltinProtocol::Dns
        | BuiltinProtocol::Esp
        | BuiltinProtocol::Icmpv4
        | BuiltinProtocol::Icmpv6
        | BuiltinProtocol::Igmp
        | BuiltinProtocol::Malformed
        | BuiltinProtocol::Ntp
        | BuiltinProtocol::Padding
        | BuiltinProtocol::Raw
        | BuiltinProtocol::Sctp
        | BuiltinProtocol::Tcp
        | BuiltinProtocol::Http
        | BuiltinProtocol::Tls => false,
    }
}

fn validate_attached_srh(packet: &Packet, srh_index: usize) -> Result<(), Error> {
    for (network_index, candidate) in packet.iter().enumerate().take(srh_index).rev() {
        if let Some(ipv6) = candidate.downcast_ref::<Ipv6>() {
            ip_path_at(
                packet,
                network_index,
                srh_index.saturating_add(1),
                IpHeader::V6(ipv6),
            )?;
            return Ok(());
        }
        if !BuiltinProtocol::of(candidate).is_some_and(BuiltinProtocol::is_ipv6_extension) {
            break;
        }
    }
    Err(Error::DetachedSegmentRoutingHeader)
}

fn push_if_specified(destinations: &mut Vec<IpAddr>, destination: IpAddr) {
    if !destination.is_unspecified() && !destinations.contains(&destination) {
        destinations.push(destination);
    }
}
