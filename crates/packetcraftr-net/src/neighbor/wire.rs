// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::{
    link::MacAddress,
    route::{
        MAX_NEIGHBOR_VLAN_TAGS, NeighborError, NeighborRequest, NeighborVlanKind, NeighborVlanTag,
    },
};
use packetcraftr_core::frame::{Frame, LinkType};

pub(super) const ETHERNET_HEADER_LENGTH: usize = 14;
pub(super) const ETHERNET_MINIMUM_WITHOUT_FCS: usize = 60;
pub(super) const VLAN_HEADER_LENGTH: usize = 4;
pub(super) const ARP_PAYLOAD_LENGTH: usize = 28;
pub(super) const IPV6_HEADER_LENGTH: usize = 40;
pub(super) const NEIGHBOR_SOLICITATION_LENGTH: usize = 32;

pub(super) const ETHERTYPE_ARP: u16 = 0x0806;
pub(super) const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
pub(super) const ETHERTYPE_SERVICE_VLAN: u16 = 0x88a8;
pub(super) const IPV6_NEXT_HEADER_ICMP: u8 = 58;
pub(super) const NEIGHBOR_SOLICITATION_TYPE: u8 = 135;
pub(super) const NEIGHBOR_ADVERTISEMENT_TYPE: u8 = 136;
pub(super) const SOURCE_LINK_LAYER_OPTION: u8 = 1;
pub(super) const TARGET_LINK_LAYER_OPTION: u8 = 2;
pub(super) const SOLICITED_ADVERTISEMENT_FLAG: u32 = 1 << 30;

pub(super) fn build_request_frame(
    request: &NeighborRequest,
) -> Result<(Bytes, MacAddress), NeighborError> {
    match (request.interface_source, request.target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            if ARP_PAYLOAD_LENGTH > request.mtu as usize {
                return Err(NeighborError::InvalidRequest {
                    message: format!(
                        "ARP request is {ARP_PAYLOAD_LENGTH} bytes but route MTU is {}",
                        request.mtu
                    ),
                });
            }
            let destination = MacAddress([0xff; 6]);
            Ok((build_arp_request(request, source, target), destination))
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let ipv6_destination = solicited_node_multicast(target);
            let destination = ipv6_multicast_mac(ipv6_destination);
            let packet_length = IPV6_HEADER_LENGTH + NEIGHBOR_SOLICITATION_LENGTH;
            if packet_length > request.mtu as usize {
                return Err(NeighborError::InvalidRequest {
                    message: format!(
                        "IPv6 neighbor solicitation is {packet_length} bytes but route MTU is {}",
                        request.mtu
                    ),
                });
            }
            Ok((
                build_neighbor_solicitation(request, source, target, ipv6_destination, destination),
                destination,
            ))
        }
        _ => Err(NeighborError::InvalidRequest {
            message: "source and target address families differ".to_owned(),
        }),
    }
}

fn build_arp_request(request: &NeighborRequest, source: Ipv4Addr, target: Ipv4Addr) -> Bytes {
    let destination = MacAddress([0xff; 6]);
    let mut frame = ethernet_prefix(
        destination,
        request.interface_mac,
        &request.vlan_tags,
        ETHERTYPE_ARP,
    );
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&[6, 4]);
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&request.interface_mac.0);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&target.octets());
    frame.resize(
        ETHERNET_MINIMUM_WITHOUT_FCS + request.vlan_tags.len() * VLAN_HEADER_LENGTH,
        0,
    );
    Bytes::from(frame)
}

fn build_neighbor_solicitation(
    request: &NeighborRequest,
    source: Ipv6Addr,
    target: Ipv6Addr,
    destination: Ipv6Addr,
    destination_mac: MacAddress,
) -> Bytes {
    let mut frame = ethernet_prefix(
        destination_mac,
        request.interface_mac,
        &request.vlan_tags,
        ETHERTYPE_IPV6,
    );
    let mut icmp = Vec::with_capacity(NEIGHBOR_SOLICITATION_LENGTH);
    icmp.extend_from_slice(&[NEIGHBOR_SOLICITATION_TYPE, 0, 0, 0]);
    icmp.extend_from_slice(&[0; 4]);
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[SOURCE_LINK_LAYER_OPTION, 1]);
    icmp.extend_from_slice(&request.interface_mac.0);
    let checksum = icmpv6_checksum(source, destination, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "NEIGHBOR_SOLICITATION_LENGTH is a fixed ICMPv6 message length far below u16::MAX"
    )]
    let solicitation_length = NEIGHBOR_SOLICITATION_LENGTH as u16;
    frame.extend_from_slice(&solicitation_length.to_be_bytes());
    frame.extend_from_slice(&[IPV6_NEXT_HEADER_ICMP, 255]);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(&icmp);
    Bytes::from(frame)
}

pub(super) fn ethernet_prefix(
    destination: MacAddress,
    source: MacAddress,
    tags: &[NeighborVlanTag],
    payload_type: u16,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(
        ETHERNET_HEADER_LENGTH + tags.len() * VLAN_HEADER_LENGTH + ARP_PAYLOAD_LENGTH,
    );
    frame.extend_from_slice(&destination.0);
    frame.extend_from_slice(&source.0);
    frame.extend_from_slice(
        &tags
            .first()
            .map_or(payload_type, |tag| tag.kind.ether_type())
            .to_be_bytes(),
    );
    for (index, tag) in tags.iter().enumerate() {
        let tci = (u16::from(tag.priority) << 13)
            | (if tag.drop_eligible { 1 << 12 } else { 0 })
            | tag.vlan_id;
        frame.extend_from_slice(&tci.to_be_bytes());
        let next = tags
            .get(index + 1)
            .map_or(payload_type, |next| next.kind.ether_type());
        frame.extend_from_slice(&next.to_be_bytes());
    }
    frame
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
    let ethernet = parse_ethernet(frame.bytes())?;
    if (ethernet.destination != request.interface_mac) || (ethernet.vlan_tags != request.vlan_tags)
    {
        return None;
    }
    match (
        request.interface_source,
        request.target,
        ethernet.ether_type,
    ) {
        (IpAddr::V4(source), IpAddr::V4(target), ETHERTYPE_ARP) => {
            match_arp_response(request, source, target, ethernet)
        }
        (IpAddr::V6(source), IpAddr::V6(target), ETHERTYPE_IPV6) => {
            match_neighbor_advertisement(source, target, ethernet)
        }
        _ => None,
    }
}

pub(super) fn is_unicast_mac(address: MacAddress) -> bool {
    address.0 != [0; 6] && address.0 != [0xff; 6] && address.0[0] & 1 == 0
}

struct EthernetView<'a> {
    destination: MacAddress,
    source: MacAddress,
    vlan_tags: Vec<NeighborVlanTag>,
    ether_type: u16,
    payload: &'a [u8],
}

fn parse_ethernet(bytes: &[u8]) -> Option<EthernetView<'_>> {
    if bytes.len() < ETHERNET_HEADER_LENGTH {
        return None;
    }
    let mut destination = [0; 6];
    destination.copy_from_slice(&bytes[..6]);
    let mut source = [0; 6];
    source.copy_from_slice(&bytes[6..12]);
    let mut ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
    let mut offset = ETHERNET_HEADER_LENGTH;
    let mut vlan_tags = Vec::new();
    while matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_SERVICE_VLAN) {
        if vlan_tags.len() >= MAX_NEIGHBOR_VLAN_TAGS {
            return None;
        }
        let header = bytes.get(offset..offset + VLAN_HEADER_LENGTH)?;
        let tci = u16::from_be_bytes([header[0], header[1]]);
        vlan_tags.push(NeighborVlanTag {
            kind: if ether_type == ETHERTYPE_SERVICE_VLAN {
                NeighborVlanKind::Ieee8021Ad
            } else {
                NeighborVlanKind::Ieee8021Q
            },
            priority: ((tci >> 13) & 7) as u8,
            drop_eligible: (tci & 0x1000) != 0,
            vlan_id: tci & 0x0fff,
        });
        ether_type = u16::from_be_bytes([header[2], header[3]]);
        offset += VLAN_HEADER_LENGTH;
    }
    Some(EthernetView {
        destination: MacAddress(destination),
        source: MacAddress(source),
        vlan_tags,
        ether_type,
        payload: &bytes[offset..],
    })
}

fn match_arp_response(
    request: &NeighborRequest,
    source: Ipv4Addr,
    target: Ipv4Addr,
    ethernet: EthernetView<'_>,
) -> Option<MacAddress> {
    let arp = ethernet.payload.get(..ARP_PAYLOAD_LENGTH)?;
    if arp[..8] != [0, 1, 0x08, 0, 6, 4, 0, 2] {
        return None;
    }
    let mut sender_mac = [0; 6];
    sender_mac.copy_from_slice(&arp[8..14]);
    let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    let mut target_mac = [0; 6];
    target_mac.copy_from_slice(&arp[18..24]);
    let target_ip = Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]);
    let sender_mac = MacAddress(sender_mac);
    if sender_ip != target
        || target_ip != source
        || target_mac != request.interface_mac.0
        || ethernet.source != sender_mac
        || !is_unicast_mac(sender_mac)
    {
        return None;
    }
    Some(sender_mac)
}

fn match_neighbor_advertisement(
    interface_source: Ipv6Addr,
    target: Ipv6Addr,
    ethernet: EthernetView<'_>,
) -> Option<MacAddress> {
    if ethernet.payload.len() < IPV6_HEADER_LENGTH {
        return None;
    }
    let ipv6 = ethernet.payload;
    if ipv6[0] >> 4 != 6 || ipv6[7] != 255 {
        return None;
    }
    let payload_length = usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]]));
    let payload = ipv6.get(IPV6_HEADER_LENGTH..IPV6_HEADER_LENGTH + payload_length)?;
    let icmp = upper_layer_icmpv6(ipv6[6], payload)?;
    if icmp.len() < 24
        || icmp[0] != NEIGHBOR_ADVERTISEMENT_TYPE
        || icmp[1] != 0
        || u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]) & SOLICITED_ADVERTISEMENT_FLAG
            == 0
    {
        return None;
    }
    let source = ipv6_address(&ipv6[8..24]);
    let destination = ipv6_address(&ipv6[24..40]);
    let advertised_target = ipv6_address(&icmp[8..24]);
    if source.is_unspecified()
        || source.is_multicast()
        || destination != interface_source
        || advertised_target != target
        || advertised_target.is_multicast()
        || icmpv6_checksum(source, destination, icmp) != 0
    {
        return None;
    }

    let mut option_offset = 24;
    let mut target_mac = None;
    while option_offset < icmp.len() {
        let header = icmp.get(option_offset..option_offset + 2)?;
        let option_length = usize::from(header[1]) * 8;
        if option_length == 0 {
            return None;
        }
        let option = icmp.get(option_offset..option_offset + option_length)?;
        if header[0] == TARGET_LINK_LAYER_OPTION {
            if option_length != 8 {
                return None;
            }
            let mut mac = [0; 6];
            mac.copy_from_slice(&option[2..8]);
            let mac = MacAddress(mac);
            if target_mac.is_some_and(|existing| existing != mac) {
                return None;
            }
            target_mac = Some(mac);
        }
        option_offset += option_length;
    }
    let target_mac = target_mac?;
    if target_mac != ethernet.source || !is_unicast_mac(target_mac) {
        return None;
    }
    Some(target_mac)
}

fn upper_layer_icmpv6(mut next_header: u8, mut payload: &[u8]) -> Option<&[u8]> {
    loop {
        match next_header {
            IPV6_NEXT_HEADER_ICMP => return Some(payload),
            0 | 43 | 60 => {
                let header = payload.get(..2)?;
                next_header = header[0];
                let length = (usize::from(header[1]) + 1).checked_mul(8)?;
                payload = payload.get(length..)?;
            }
            51 => {
                let header = payload.get(..2)?;
                next_header = header[0];
                let length = (usize::from(header[1]) + 2).checked_mul(4)?;
                payload = payload.get(length..)?;
            }
            // RFC 6980 requires receivers to discard fragmented NDP messages.
            44 => return None,
            _ => return None,
        }
    }
}

fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let target_octets = target.octets();
    let mut multicast = [0_u8; 16];
    multicast[0] = 0xff;
    multicast[1] = 0x02;
    multicast[11] = 0x01;
    multicast[12] = 0xff;
    multicast[13..].copy_from_slice(&target_octets[13..]);
    Ipv6Addr::from(multicast)
}

fn ipv6_multicast_mac(address: Ipv6Addr) -> MacAddress {
    let address_octets = address.octets();
    MacAddress([
        0x33,
        0x33,
        address_octets[12],
        address_octets[13],
        address_octets[14],
        address_octets[15],
    ])
}

pub(super) fn ipv6_address(bytes: &[u8]) -> Ipv6Addr {
    let mut address = [0; 16];
    address.copy_from_slice(bytes);
    Ipv6Addr::from(address)
}

pub(super) fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> u16 {
    let length = u32::try_from(message.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes();
    checksum(&[
        &source.octets(),
        &destination.octets(),
        &length,
        &[0, 0, 0, IPV6_NEXT_HEADER_ICMP],
        message,
    ])
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the fold loop only exits once sum >> 16 is zero, so sum is at most 0xffff"
)]
pub(super) fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u64;
    let mut pending = None;
    for part in parts {
        let mut bytes = *part;
        if let Some(high) = pending.take() {
            if let Some((&low, rest)) = bytes.split_first() {
                sum += u64::from(u16::from_be_bytes([high, low]));
                bytes = rest;
            } else {
                pending = Some(high);
                continue;
            }
        }
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        pending = chunks.remainder().first().copied();
    }
    if let Some(high) = pending {
        sum += u64::from(u16::from_be_bytes([high, 0]));
    }
    while sum > u64::from(u16::MAX) {
        sum = (sum & u64::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::route::InterfaceId;

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
            Err(NeighborError::InvalidRequest { .. })
        ));

        let mut ipv6 = request(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        );
        ipv6.mtu = u32::try_from(IPV6_HEADER_LENGTH + NEIGHBOR_SOLICITATION_LENGTH - 1)
            .expect("fixed NDP length fits u32");
        assert!(matches!(
            build_request_frame(&ipv6),
            Err(NeighborError::InvalidRequest { .. })
        ));

        let mixed = request(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        );
        assert!(matches!(
            build_request_frame(&mixed),
            Err(NeighborError::InvalidRequest { .. })
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

        let mut wrong_interface = capture(bytes.clone());
        wrong_interface.interface = Some(request.interface.index + 1);
        assert_eq!(match_neighbor_response(&request, &wrong_interface), None);

        let wrong_link =
            Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).expect("fixture frame");
        assert_eq!(match_neighbor_response(&request, &wrong_link), None);
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
    fn checksum_is_independent_of_part_boundaries_and_handles_odd_bytes() {
        let contiguous = checksum(&[&[1, 2, 3, 4, 5]]);
        let split = checksum(&[&[1], &[], &[2, 3], &[4], &[5]]);
        assert_eq!(contiguous, split);
        assert_eq!(checksum(&[&[]]), u16::MAX);
        assert_eq!(checksum(&[&[0xff, 0xff]]), 0);
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
