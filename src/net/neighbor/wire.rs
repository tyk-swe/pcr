const ETHERNET_HEADER_LENGTH: usize = 14;
const ETHERNET_MINIMUM_WITHOUT_FCS: usize = 60;
const VLAN_HEADER_LENGTH: usize = 4;
const ARP_PAYLOAD_LENGTH: usize = 28;
const IPV6_HEADER_LENGTH: usize = 40;
const NEIGHBOR_SOLICITATION_LENGTH: usize = 32;

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_SERVICE_VLAN: u16 = 0x88a8;
const IPV6_NEXT_HEADER_ICMP: u8 = 58;
const NEIGHBOR_SOLICITATION_TYPE: u8 = 135;
const NEIGHBOR_ADVERTISEMENT_TYPE: u8 = 136;
const SOURCE_LINK_LAYER_OPTION: u8 = 1;
const TARGET_LINK_LAYER_OPTION: u8 = 2;
const SOLICITED_ADVERTISEMENT_FLAG: u32 = 1 << 30;

fn build_request_frame(request: &NeighborRequest) -> Result<(Bytes, MacAddress), NeighborError> {
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
    frame.extend_from_slice(&(NEIGHBOR_SOLICITATION_LENGTH as u16).to_be_bytes());
    frame.extend_from_slice(&[IPV6_NEXT_HEADER_ICMP, 255]);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(&icmp);
    Bytes::from(frame)
}

fn ethernet_prefix(
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

fn match_neighbor_response(
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
    let ethernet = parse_ethernet(&frame.bytes)?;
    if ethernet.destination != request.interface_mac || ethernet.vlan_tags != request.vlan_tags {
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
    if ipv6[0] >> 4 != 6 || ipv6[6] != IPV6_NEXT_HEADER_ICMP || ipv6[7] != 255 {
        return None;
    }
    let payload_length = usize::from(u16::from_be_bytes([ipv6[4], ipv6[5]]));
    let icmp = ipv6.get(IPV6_HEADER_LENGTH..IPV6_HEADER_LENGTH + payload_length)?;
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

fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let target = target.octets();
    let mut multicast = [0_u8; 16];
    multicast[0] = 0xff;
    multicast[1] = 0x02;
    multicast[11] = 0x01;
    multicast[12] = 0xff;
    multicast[13..].copy_from_slice(&target[13..]);
    Ipv6Addr::from(multicast)
}

fn ipv6_multicast_mac(address: Ipv6Addr) -> MacAddress {
    let address = address.octets();
    MacAddress([
        0x33,
        0x33,
        address[12],
        address[13],
        address[14],
        address[15],
    ])
}

fn ipv6_address(bytes: &[u8]) -> Ipv6Addr {
    let mut address = [0; 16];
    address.copy_from_slice(bytes);
    Ipv6Addr::from(address)
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> u16 {
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

fn checksum(parts: &[&[u8]]) -> u16 {
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
