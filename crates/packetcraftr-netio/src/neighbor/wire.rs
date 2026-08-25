// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private neighbor-wire facade over Ethernet, ARP, and IPv6 NDP owners.

use std::net::IpAddr;
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::Request as NeighborRequest;
use crate::link::MacAddress;
use packetcraftr_core::frame::{Frame, LinkType};

mod arp;
mod ethernet;
mod ndp;

#[cfg(test)]
use self::{
    arp::PAYLOAD_LENGTH as ARP_PAYLOAD_LENGTH,
    ethernet::{
        ETHERTYPE_ARP, ETHERTYPE_IPV6, ETHERTYPE_SERVICE_VLAN, ETHERTYPE_VLAN,
        HEADER_LENGTH as ETHERNET_HEADER_LENGTH,
        MINIMUM_WITHOUT_FCS as ETHERNET_MINIMUM_WITHOUT_FCS, parse as parse_ethernet,
        prefix as ethernet_prefix,
    },
    ndp::{
        ADVERTISEMENT_TYPE as NEIGHBOR_ADVERTISEMENT_TYPE, IPV6_HEADER_LENGTH,
        NEXT_HEADER_ICMP as IPV6_NEXT_HEADER_ICMP,
        SOLICITATION_LENGTH as NEIGHBOR_SOLICITATION_LENGTH,
        SOLICITATION_TYPE as NEIGHBOR_SOLICITATION_TYPE, SOLICITED_ADVERTISEMENT_FLAG,
        TARGET_LINK_LAYER_OPTION, icmpv6_checksum, ipv6_address, solicited_node_multicast,
        upper_layer_icmpv6,
    },
};
#[cfg(test)]
use super::{
    MAX_VLAN_TAGS as MAX_NEIGHBOR_VLAN_TAGS, VlanKind as NeighborVlanKind,
    VlanTag as NeighborVlanTag,
};
pub(super) fn build_request_frame(
    request: &NeighborRequest,
) -> Result<(Bytes, MacAddress), crate::neighbor::Error> {
    match (request.interface_source, request.target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            if arp::PAYLOAD_LENGTH > request.mtu as usize {
                return Err(crate::neighbor::Error::InvalidRequest {
                    message: format!(
                        "ARP request is {} bytes but route MTU is {}",
                        arp::PAYLOAD_LENGTH,
                        request.mtu
                    ),
                });
            }
            let destination = MacAddress([0xff; 6]);
            Ok((arp::build_request(request, source, target), destination))
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let ipv6_destination = ndp::solicited_node_multicast(target);
            let destination = ndp::ipv6_multicast_mac(ipv6_destination);
            let packet_length = ndp::IPV6_HEADER_LENGTH + ndp::SOLICITATION_LENGTH;
            if packet_length > request.mtu as usize {
                return Err(crate::neighbor::Error::InvalidRequest {
                    message: format!(
                        "IPv6 neighbor solicitation is {packet_length} bytes but route MTU is {}",
                        request.mtu
                    ),
                });
            }
            Ok((
                ndp::build_solicitation(request, source, target, ipv6_destination, destination),
                destination,
            ))
        }
        _ => Err(crate::neighbor::Error::InvalidRequest {
            message: "source and target address families differ".to_owned(),
        }),
    }
}

pub(super) fn match_neighbor_response(
    request: &NeighborRequest,
    frame: &Frame,
) -> Option<MacAddress> {
    if frame.link_type != LinkType::ETHERNET
        || frame
            .interface
            .is_some_and(|index| index != request.interface.index)
    {
        return None;
    }
    let ethernet = ethernet::parse(frame.bytes())?;
    if ethernet.destination != request.interface_mac || ethernet.vlan_tags != request.vlan_tags {
        return None;
    }
    match (
        request.interface_source,
        request.target,
        ethernet.ether_type,
    ) {
        (IpAddr::V4(source), IpAddr::V4(target), ethernet::ETHERTYPE_ARP) => {
            arp::match_response(request, source, target, ethernet)
        }
        (IpAddr::V6(source), IpAddr::V6(target), ethernet::ETHERTYPE_IPV6) => {
            ndp::match_advertisement(source, target, ethernet)
        }
        _ => None,
    }
}

pub(super) fn is_unicast_mac(address: MacAddress) -> bool {
    ethernet::is_unicast_mac(address)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::interface::Id as InterfaceId;

    fn request(source: IpAddr, target: IpAddr) -> NeighborRequest {
        NeighborRequest {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            interface_source: source,
            interface_mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
            target,
            vlan_tags: Vec::new(),
            mtu: 1_500,
            link_type: LinkType::ETHERNET,
        }
    }

    fn capture(bytes: impl Into<Bytes>) -> Frame {
        Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes)
            .expect("fixture frame must fit")
    }

    #[test]
    fn arp_request_has_exact_broadcast_envelope_and_wire_fields() {
        let request = request(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
        );
        let (frame, destination) = build_request_frame(&request).expect("ARP request");

        assert_eq!(destination, MacAddress([0xff; 6]));
        assert_eq!(frame.len(), ETHERNET_MINIMUM_WITHOUT_FCS);
        assert_eq!(&frame[..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &request.interface_mac.0);
        assert_eq!(&frame[12..14], &ETHERTYPE_ARP.to_be_bytes());
        assert_eq!(&frame[14..22], &[0, 1, 0x08, 0, 6, 4, 0, 1]);
        assert_eq!(&frame[22..28], &request.interface_mac.0);
        assert_eq!(&frame[28..32], &[192, 0, 2, 1]);
        assert_eq!(&frame[38..42], &[192, 0, 2, 99]);
        assert_eq!(
            frame.as_ref(),
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
                0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x63,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn neighbor_solicitation_uses_solicited_multicast_and_valid_checksum() {
        let source = "2001:db8::1".parse::<Ipv6Addr>().expect("IPv6 source");
        let target = "2001:db8::abcd".parse::<Ipv6Addr>().expect("IPv6 target");
        let request = request(IpAddr::V6(source), IpAddr::V6(target));
        let (frame, destination_mac) =
            build_request_frame(&request).expect("neighbor solicitation");

        let destination = solicited_node_multicast(target);
        assert_eq!(
            destination,
            "ff02::1:ff00:abcd".parse::<Ipv6Addr>().expect("multicast")
        );
        assert_eq!(
            destination_mac,
            MacAddress([0x33, 0x33, 0xff, 0x00, 0xab, 0xcd])
        );
        assert_eq!(&frame[..6], &destination_mac.0);
        assert_eq!(&frame[12..14], &ETHERTYPE_IPV6.to_be_bytes());
        let ipv6 = &frame[ETHERNET_HEADER_LENGTH..];
        assert_eq!(ipv6[0] >> 4, 6);
        assert_eq!(ipv6[6], IPV6_NEXT_HEADER_ICMP);
        assert_eq!(ipv6[7], 255);
        assert_eq!(ipv6_address(&ipv6[8..24]), source);
        assert_eq!(ipv6_address(&ipv6[24..40]), destination);
        assert_eq!(ipv6[40], NEIGHBOR_SOLICITATION_TYPE);
        assert_eq!(icmpv6_checksum(source, destination, &ipv6[40..]), 0);
        assert_eq!(
            frame.as_ref(),
            &[
                0x33, 0x33, 0xff, 0x00, 0xab, 0xcd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xdd,
                0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x3a, 0xff, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0xab, 0xcd, 0x87, 0x00,
                0xc4, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]
        );
    }

    #[test]
    fn request_builder_rejects_family_and_mtu_mismatches() {
        let mut ipv4 = request(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        );
        ipv4.mtu = u32::try_from(ARP_PAYLOAD_LENGTH - 1).expect("fixed ARP length fits u32");
        assert!(matches!(
            build_request_frame(&ipv4),
            Err(crate::neighbor::Error::InvalidRequest { .. })
        ));

        let mut ipv6 = request(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        );
        ipv6.mtu = u32::try_from(IPV6_HEADER_LENGTH + NEIGHBOR_SOLICITATION_LENGTH - 1)
            .expect("fixed NDP length fits u32");
        assert!(matches!(
            build_request_frame(&ipv6),
            Err(crate::neighbor::Error::InvalidRequest { .. })
        ));

        let mixed = request(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        );
        assert!(matches!(
            build_request_frame(&mixed),
            Err(crate::neighbor::Error::InvalidRequest { .. })
        ));
    }

    #[test]
    fn ethernet_prefix_encodes_stacked_vlan_metadata_in_order() {
        let tags = [
            NeighborVlanTag {
                kind: NeighborVlanKind::Ieee8021Ad,
                priority: 5,
                drop_eligible: true,
                vlan_id: 100,
            },
            NeighborVlanTag {
                kind: NeighborVlanKind::Ieee8021Q,
                priority: 1,
                drop_eligible: false,
                vlan_id: 200,
            },
        ];
        let bytes = ethernet_prefix(
            MacAddress([0x02, 0, 0, 0, 0, 2]),
            MacAddress([0x02, 0, 0, 0, 0, 1]),
            &tags,
            ETHERTYPE_ARP,
        );

        assert_eq!(&bytes[12..14], &ETHERTYPE_SERVICE_VLAN.to_be_bytes());
        assert_eq!(
            u16::from_be_bytes([bytes[14], bytes[15]]),
            (5 << 13) | (1 << 12) | 100
        );
        assert_eq!(&bytes[16..18], &ETHERTYPE_VLAN.to_be_bytes());
        assert_eq!(u16::from_be_bytes([bytes[18], bytes[19]]), (1 << 13) | 200);
        assert_eq!(&bytes[20..22], &ETHERTYPE_ARP.to_be_bytes());

        let parsed = parse_ethernet(&bytes).expect("stacked Ethernet header");
        assert_eq!(parsed.vlan_tags, tags);
        assert_eq!(parsed.ether_type, ETHERTYPE_ARP);
        assert!(parsed.payload.is_empty());
    }

    fn arp_response(request: &NeighborRequest, sender: MacAddress) -> Vec<u8> {
        let (IpAddr::V4(interface_source), IpAddr::V4(target)) =
            (request.interface_source, request.target)
        else {
            panic!("ARP fixture must use IPv4")
        };
        let mut frame = ethernet_prefix(
            request.interface_mac,
            sender,
            &request.vlan_tags,
            ETHERTYPE_ARP,
        );
        frame.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 2]);
        frame.extend_from_slice(&sender.0);
        frame.extend_from_slice(&target.octets());
        frame.extend_from_slice(&request.interface_mac.0);
        frame.extend_from_slice(&interface_source.octets());
        frame
    }

    #[test]
    fn arp_response_matcher_accepts_only_exact_correlated_evidence() {
        let request = request(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        );
        let sender = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let bytes = arp_response(&request, sender);
        assert_eq!(
            match_neighbor_response(&request, &capture(bytes.clone())),
            Some(sender)
        );

        let mut wrong_operation = bytes.clone();
        wrong_operation[21] = 1;
        assert_eq!(
            match_neighbor_response(&request, &capture(wrong_operation)),
            None
        );

        let mut wrong_sender = bytes.clone();
        wrong_sender[6] ^= 1;
        assert_eq!(
            match_neighbor_response(&request, &capture(wrong_sender)),
            None
        );

        for (offset, field) in [
            (0, "Ethernet destination"),
            (31, "ARP sender address"),
            (37, "ARP target hardware address"),
            (41, "ARP target address"),
        ] {
            let mut mismatched = bytes.clone();
            mismatched[offset] ^= 1;
            assert_eq!(
                match_neighbor_response(&request, &capture(mismatched)),
                None,
                "{field} must correlate exactly"
            );
        }

        let mut multicast_sender = bytes.clone();
        multicast_sender[6] |= 1;
        multicast_sender[22] |= 1;
        assert_eq!(
            match_neighbor_response(&request, &capture(multicast_sender)),
            None
        );

        let mut wrong_interface = capture(bytes.clone());
        wrong_interface.interface = Some(request.interface.index + 1);
        assert_eq!(match_neighbor_response(&request, &wrong_interface), None);

        let wrong_link =
            Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).expect("fixture frame");
        assert_eq!(match_neighbor_response(&request, &wrong_link), None);

        let mut tagged = request.clone();
        tagged.vlan_tags.push(NeighborVlanTag {
            kind: NeighborVlanKind::Ieee8021Q,
            priority: 3,
            drop_eligible: true,
            vlan_id: 409,
        });
        let tagged_bytes = arp_response(&tagged, sender);
        assert_eq!(
            match_neighbor_response(&tagged, &capture(tagged_bytes.clone())),
            Some(sender)
        );
        assert_eq!(
            match_neighbor_response(&request, &capture(tagged_bytes)),
            None
        );
    }

    fn neighbor_advertisement(request: &NeighborRequest, sender: MacAddress) -> Vec<u8> {
        let (IpAddr::V6(interface_source), IpAddr::V6(target)) =
            (request.interface_source, request.target)
        else {
            panic!("NDP fixture must use IPv6")
        };
        let mut icmp = Vec::new();
        icmp.extend_from_slice(&[NEIGHBOR_ADVERTISEMENT_TYPE, 0, 0, 0]);
        icmp.extend_from_slice(&SOLICITED_ADVERTISEMENT_FLAG.to_be_bytes());
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&[TARGET_LINK_LAYER_OPTION, 1]);
        icmp.extend_from_slice(&sender.0);
        let checksum = icmpv6_checksum(target, interface_source, &icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = ethernet_prefix(
            request.interface_mac,
            sender,
            &request.vlan_tags,
            ETHERTYPE_IPV6,
        );
        frame.extend_from_slice(&[0x60, 0, 0, 0]);
        frame.extend_from_slice(
            &u16::try_from(icmp.len())
                .expect("fixture ICMP length fits u16")
                .to_be_bytes(),
        );
        frame.extend_from_slice(&[IPV6_NEXT_HEADER_ICMP, 255]);
        frame.extend_from_slice(&target.octets());
        frame.extend_from_slice(&interface_source.octets());
        frame.extend_from_slice(&icmp);
        frame
    }

    fn resign_neighbor_advertisement(frame: &mut [u8]) {
        let ipv6_offset = ETHERNET_HEADER_LENGTH;
        let icmp_offset = ipv6_offset + IPV6_HEADER_LENGTH;
        let source = ipv6_address(&frame[ipv6_offset + 8..ipv6_offset + 24]);
        let destination = ipv6_address(&frame[ipv6_offset + 24..ipv6_offset + 40]);
        frame[icmp_offset + 2..icmp_offset + 4].fill(0);
        let checksum = icmpv6_checksum(source, destination, &frame[icmp_offset..]);
        frame[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
    }

    fn with_ipv6_extension(mut frame: Vec<u8>, extension_type: u8) -> Vec<u8> {
        let ipv6_offset = ETHERNET_HEADER_LENGTH;
        let payload_length = u16::from_be_bytes([frame[ipv6_offset + 4], frame[ipv6_offset + 5]]);
        frame[ipv6_offset + 4..ipv6_offset + 6].copy_from_slice(
            &payload_length
                .checked_add(8)
                .expect("fixture length")
                .to_be_bytes(),
        );
        frame[ipv6_offset + 6] = extension_type;
        frame.splice(
            ipv6_offset + IPV6_HEADER_LENGTH..ipv6_offset + IPV6_HEADER_LENGTH,
            [IPV6_NEXT_HEADER_ICMP, 0, 0, 0, 0, 0, 0, 0],
        );
        frame
    }

    #[test]
    fn neighbor_advertisement_matcher_validates_flags_checksum_and_option() {
        let request = request(
            IpAddr::V6("2001:db8::1".parse().expect("source")),
            IpAddr::V6("2001:db8::2".parse().expect("target")),
        );
        let sender = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let bytes = neighbor_advertisement(&request, sender);
        assert_eq!(
            match_neighbor_response(&request, &capture(bytes.clone())),
            Some(sender)
        );

        let mut bad_checksum = bytes.clone();
        *bad_checksum.last_mut().expect("last option byte") ^= 1;
        assert_eq!(
            match_neighbor_response(&request, &capture(bad_checksum)),
            None
        );

        let mut bad_hop_limit = bytes.clone();
        bad_hop_limit[ETHERNET_HEADER_LENGTH + 7] = 64;
        assert_eq!(
            match_neighbor_response(&request, &capture(bad_hop_limit)),
            None
        );

        let mut missing_flag = bytes;
        let flag_offset = ETHERNET_HEADER_LENGTH + IPV6_HEADER_LENGTH + 4;
        missing_flag[flag_offset..flag_offset + 4].fill(0);
        assert_eq!(
            match_neighbor_response(&request, &capture(missing_flag)),
            None
        );

        let mut missing_option = neighbor_advertisement(&request, sender);
        let option_offset = ETHERNET_HEADER_LENGTH + IPV6_HEADER_LENGTH + 24;
        missing_option[option_offset] = 99;
        resign_neighbor_advertisement(&mut missing_option);
        assert_eq!(
            match_neighbor_response(&request, &capture(missing_option)),
            None
        );

        let mut zero_length_option = neighbor_advertisement(&request, sender);
        zero_length_option[option_offset + 1] = 0;
        resign_neighbor_advertisement(&mut zero_length_option);
        assert_eq!(
            match_neighbor_response(&request, &capture(zero_length_option)),
            None
        );
    }

    #[test]
    fn neighbor_advertisement_accepts_extensions_and_rejects_fragments() {
        let request = request(
            IpAddr::V6("2001:db8::1".parse().expect("source")),
            IpAddr::V6("2001:db8::2".parse().expect("target")),
        );
        let sender = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let bytes = neighbor_advertisement(&request, sender);

        let extended = with_ipv6_extension(bytes.clone(), 0);
        assert_eq!(
            match_neighbor_response(&request, &capture(extended)),
            Some(sender)
        );

        let fragmented = with_ipv6_extension(bytes, 44);
        assert_eq!(
            match_neighbor_response(&request, &capture(fragmented)),
            None
        );
    }

    #[test]
    fn upper_layer_parser_handles_extension_headers_and_rejects_fragments() {
        assert_eq!(
            upper_layer_icmpv6(IPV6_NEXT_HEADER_ICMP, &[1, 2]),
            Some(&[1, 2][..])
        );
        assert_eq!(
            upper_layer_icmpv6(0, &[IPV6_NEXT_HEADER_ICMP, 0, 0, 0, 0, 0, 0, 0, 9]),
            Some(&[9][..])
        );
        assert_eq!(
            upper_layer_icmpv6(51, &[IPV6_NEXT_HEADER_ICMP, 0, 0, 0, 0, 0, 0, 0, 7]),
            Some(&[7][..])
        );
        assert_eq!(upper_layer_icmpv6(44, &[0; 8]), None);
        assert_eq!(upper_layer_icmpv6(6, &[0; 8]), None);
        assert_eq!(upper_layer_icmpv6(0, &[IPV6_NEXT_HEADER_ICMP]), None);
    }

    #[test]
    fn mac_validation_and_ethernet_parser_reject_invalid_shapes() {
        assert!(is_unicast_mac(MacAddress([0x02, 0, 0, 0, 0, 1])));
        assert!(!is_unicast_mac(MacAddress([0; 6])));
        assert!(!is_unicast_mac(MacAddress([0xff; 6])));
        assert!(!is_unicast_mac(MacAddress([0x01, 0, 0, 0, 0, 1])));
        assert!(parse_ethernet(&[0; ETHERNET_HEADER_LENGTH - 1]).is_none());

        let mut too_many_tags = vec![0_u8; ETHERNET_HEADER_LENGTH];
        too_many_tags[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        for _ in 0..=MAX_NEIGHBOR_VLAN_TAGS {
            too_many_tags.extend_from_slice(&[0, 1, 0x81, 0]);
        }
        assert!(parse_ethernet(&too_many_tags).is_none());
    }
}
