// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pseudo-header construction shared by the transport and ICMPv6 codecs.

use std::net::IpAddr;

use packetcraftr_packet::{
    codec::{CodecError, LayerEncodeContext, NetworkEnvelope},
    layer::Layer,
};

use super::super::common::{invalid, network_from_addresses};

use super::{Ipv4, Ipv6};

pub(super) fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    // AH participates in the IPv6 extension chain (RFC 8200), so the
    // pseudo-header scan for the final destination walks through it.
    matches!(
        layer.protocol_id().as_str(),
        "ah" | "ipv6_hop_by_hop" | "ipv6_destination_options" | "ipv6_fragment" | "ipv6_srh"
    )
}

pub(crate) fn encode_network(
    context: &LayerEncodeContext<'_>,
) -> Result<NetworkEnvelope, CodecError> {
    for index in (0..context.index).rev() {
        let Some(layer) = context.packet.layer(index) else {
            continue;
        };
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            let source = if ipv4.source.is_unspecified() && inherit_context {
                context
                    .build_context
                    .source
                    .and_then(|source| match source {
                        IpAddr::V4(source) => Some(source),
                        IpAddr::V6(_) => None,
                    })
                    .unwrap_or(ipv4.source)
            } else {
                ipv4.source
            };
            let destination = if ipv4.destination.is_unspecified() && inherit_context {
                context
                    .build_context
                    .destination
                    .and_then(|destination| match destination {
                        IpAddr::V4(destination) => Some(destination),
                        IpAddr::V6(_) => None,
                    })
                    .unwrap_or(ipv4.destination)
            } else {
                ipv4.destination
            };
            return Ok(network_from_addresses(source.into(), destination.into()));
        }
        if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            // Only routing headers inside the nearest IPv6 envelope can
            // replace its pseudo-header destination. An SRH belonging to an
            // outer tunnel must not affect an encapsulated transport.
            let segment_routing_destination = ((index + 1)..context.index)
                .filter_map(|candidate_index| context.packet.layer(candidate_index))
                .take_while(|candidate| is_ipv6_extension_layer(*candidate))
                .filter_map(|candidate| {
                    candidate
                        .as_any()
                        .downcast_ref::<super::super::ipv6::SegmentRoutingHeader>()?
                        .segments
                        .last()
                        .copied()
                })
                .last();
            let source = if ipv6.source.is_unspecified() && inherit_context {
                context
                    .build_context
                    .source
                    .and_then(|source| match source {
                        IpAddr::V6(source) => Some(source),
                        IpAddr::V4(_) => None,
                    })
                    .unwrap_or(ipv6.source)
            } else {
                ipv6.source
            };
            let destination = if ipv6.destination.is_unspecified() && inherit_context {
                context
                    .build_context
                    .destination
                    .and_then(|destination| match destination {
                        IpAddr::V6(destination) => Some(destination),
                        IpAddr::V4(_) => None,
                    })
                    .unwrap_or(ipv6.destination)
            } else {
                ipv6.destination
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
            "transport",
            "transport checksum requires matching source and destination IP addresses",
        )),
    }
}

pub(super) fn is_outer_network_layer(packet: &packetcraftr_packet::Packet, index: usize) -> bool {
    !packet
        .iter()
        .take(index)
        .any(|layer| matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6"))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;
    use packetcraftr_packet::{
        Packet,
        build::{BuildContext, BuildMode},
        codec::LayerEncodeContext,
        layer::Raw,
    };

    use super::*;
    use crate::ipv6::{DestinationOptions, Fragment, HopByHop, SegmentRoutingHeader};

    fn context<'a>(
        packet: &'a Packet,
        index: usize,
        build_context: &'a BuildContext,
        registry: &'a packetcraftr_packet::registry::ProtocolRegistry,
    ) -> LayerEncodeContext<'a> {
        LayerEncodeContext {
            packet,
            index,
            build_context,
            mode: BuildMode::Strict,
            registry,
            child: None,
            remaining_packet_bytes: usize::MAX,
        }
    }

    #[test]
    fn matching_build_context_supplies_network_without_an_ip_layer() {
        let mut packet = Packet::new();
        packet.push(Raw::new(Bytes::new()));
        let registry = crate::builtin::registry().unwrap();
        for (source, destination) in [
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            ),
            (
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                IpAddr::V6("2001:db8::2".parse().unwrap()),
            ),
        ] {
            let build = BuildContext {
                source: Some(source),
                destination: Some(destination),
                ..BuildContext::default()
            };
            assert_eq!(
                encode_network(&context(&packet, 1, &build, &registry)).unwrap(),
                NetworkEnvelope {
                    source,
                    destination
                }
            );
        }
    }

    #[test]
    fn absent_or_mismatched_context_is_rejected_without_an_ip_layer() {
        let mut packet = Packet::new();
        packet.push(Raw::new(Bytes::new()));
        let registry = crate::builtin::registry().unwrap();
        let mismatched = BuildContext {
            source: Some(Ipv4Addr::LOCALHOST.into()),
            destination: Some(Ipv6Addr::LOCALHOST.into()),
            ..BuildContext::default()
        };
        for build in [BuildContext::default(), mismatched] {
            assert!(encode_network(&context(&packet, 1, &build, &registry)).is_err());
        }
    }

    #[test]
    fn outer_unspecified_ipv4_inherits_only_matching_context_addresses() {
        let mut packet = Packet::new();
        packet.push(Ipv4::default()).push(Raw::new(Bytes::new()));
        let registry = crate::builtin::registry().unwrap();
        let build = BuildContext {
            source: Some(Ipv4Addr::new(192, 0, 2, 1).into()),
            destination: Some(Ipv4Addr::new(192, 0, 2, 2).into()),
            ..BuildContext::default()
        };
        let network = encode_network(&context(&packet, 2, &build, &registry)).unwrap();
        assert_eq!(network.source, build.source.unwrap());
        assert_eq!(network.destination, build.destination.unwrap());

        let wrong_family = BuildContext {
            source: Some(Ipv6Addr::LOCALHOST.into()),
            destination: Some(Ipv6Addr::LOCALHOST.into()),
            ..BuildContext::default()
        };
        let network = encode_network(&context(&packet, 2, &wrong_family, &registry)).unwrap();
        assert_eq!(network.source, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(network.destination, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn inner_network_layer_does_not_inherit_outer_build_context() {
        let mut packet = Packet::new();
        packet
            .push(Ipv6::default())
            .push(Ipv4::default())
            .push(Raw::new(Bytes::new()));
        let registry = crate::builtin::registry().unwrap();
        let build = BuildContext {
            source: Some(Ipv4Addr::LOCALHOST.into()),
            destination: Some(Ipv4Addr::BROADCAST.into()),
            ..BuildContext::default()
        };
        let network = encode_network(&context(&packet, 3, &build, &registry)).unwrap();
        assert_eq!(network.source, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(network.destination, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(is_outer_network_layer(&packet, 0));
        assert!(!is_outer_network_layer(&packet, 1));
    }

    #[test]
    fn nearest_srh_final_segment_replaces_ipv6_pseudo_header_destination() {
        let original: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let final_segment: Ipv6Addr = "2001:db8::30".parse().unwrap();
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: original,
                ..Ipv6::default()
            })
            .push(HopByHop::default())
            .push(SegmentRoutingHeader {
                segments: vec!["2001:db8::20".parse().unwrap(), final_segment],
                ..SegmentRoutingHeader::default()
            })
            .push(DestinationOptions::default())
            .push(Fragment::default())
            .push(Raw::new(Bytes::new()));
        let registry = crate::builtin::registry().unwrap();
        let network = encode_network(&context(
            &packet,
            packet.len(),
            &BuildContext::default(),
            &registry,
        ))
        .unwrap();
        assert_eq!(network.destination, IpAddr::V6(final_segment));
        assert!(is_ipv6_extension_layer(packet.layer(1).unwrap()));
        assert!(is_ipv6_extension_layer(packet.layer(2).unwrap()));
        assert!(is_ipv6_extension_layer(packet.layer(3).unwrap()));
        assert!(is_ipv6_extension_layer(packet.layer(4).unwrap()));
        assert!(!is_ipv6_extension_layer(packet.layer(5).unwrap()));
    }

    #[test]
    fn nonextension_layer_stops_srh_search() {
        let original: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: original,
                ..Ipv6::default()
            })
            .push(Raw::new(Bytes::new()))
            .push(SegmentRoutingHeader {
                segments: vec!["2001:db8::30".parse().unwrap()],
                ..SegmentRoutingHeader::default()
            })
            .push(Raw::new(Bytes::new()));
        let registry = crate::builtin::registry().unwrap();
        let network = encode_network(&context(
            &packet,
            packet.len(),
            &BuildContext::default(),
            &registry,
        ))
        .unwrap();
        assert_eq!(network.destination, IpAddr::V6(original));
    }
}
