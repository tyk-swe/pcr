// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IPv6 Neighbor Discovery construction, extension walking, and validation.

use std::net::Ipv6Addr;

use bytes::Bytes;

use super::ethernet::{self, View};
use crate::{checksum, link::MacAddress, neighbor::Request as NeighborRequest};

pub(super) const IPV6_HEADER_LENGTH: usize = 40;
pub(super) const SOLICITATION_LENGTH: usize = 32;
pub(super) const NEXT_HEADER_ICMP: u8 = 58;
pub(super) const SOLICITATION_TYPE: u8 = 135;
pub(super) const ADVERTISEMENT_TYPE: u8 = 136;
pub(super) const SOURCE_LINK_LAYER_OPTION: u8 = 1;
pub(super) const TARGET_LINK_LAYER_OPTION: u8 = 2;
pub(super) const SOLICITED_ADVERTISEMENT_FLAG: u32 = 1 << 30;

pub(super) fn build_solicitation(
    request: &NeighborRequest,
    source: Ipv6Addr,
    target: Ipv6Addr,
    destination: Ipv6Addr,
    destination_mac: MacAddress,
) -> Bytes {
    let mut frame = ethernet::prefix(
        destination_mac,
        request.interface_mac,
        &request.vlan_tags,
        ethernet::ETHERTYPE_IPV6,
    );
    let mut icmp = Vec::with_capacity(SOLICITATION_LENGTH);
    icmp.extend_from_slice(&[SOLICITATION_TYPE, 0, 0, 0]);
    icmp.extend_from_slice(&[0; 4]);
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[SOURCE_LINK_LAYER_OPTION, 1]);
    icmp.extend_from_slice(&request.interface_mac.0);
    let checksum = icmpv6_checksum(source, destination, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "SOLICITATION_LENGTH is fixed far below u16::MAX"
    )]
    let solicitation_length = SOLICITATION_LENGTH as u16;
    frame.extend_from_slice(&solicitation_length.to_be_bytes());
    frame.extend_from_slice(&[NEXT_HEADER_ICMP, 255]);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&destination.octets());
    frame.extend_from_slice(&icmp);
    Bytes::from(frame)
}

pub(super) fn match_advertisement(
    interface_source: Ipv6Addr,
    target: Ipv6Addr,
    ethernet: View<'_>,
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
        || icmp[0] != ADVERTISEMENT_TYPE
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
    if target_mac != ethernet.source || !ethernet::is_unicast_mac(target_mac) {
        return None;
    }
    Some(target_mac)
}

pub(super) fn upper_layer_icmpv6(mut next_header: u8, mut payload: &[u8]) -> Option<&[u8]> {
    loop {
        match next_header {
            NEXT_HEADER_ICMP => return Some(payload),
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

pub(super) fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let target_octets = target.octets();
    let mut multicast = [0_u8; 16];
    multicast[0] = 0xff;
    multicast[1] = 0x02;
    multicast[11] = 0x01;
    multicast[12] = 0xff;
    multicast[13..].copy_from_slice(&target_octets[13..]);
    Ipv6Addr::from(multicast)
}

pub(super) fn ipv6_multicast_mac(address: Ipv6Addr) -> MacAddress {
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
    checksum::compute_parts(&[
        &source.octets(),
        &destination.octets(),
        &length,
        &[0, 0, 0, NEXT_HEADER_ICMP],
        message,
    ])
}
