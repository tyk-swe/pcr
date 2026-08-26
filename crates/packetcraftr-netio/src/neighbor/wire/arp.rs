// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! ARP request construction and exact response correlation.

use std::net::Ipv4Addr;

use bytes::Bytes;

use super::ethernet::{self, View};
use crate::{link::MacAddress, neighbor::Request as NeighborRequest};

pub(super) const PAYLOAD_LENGTH: usize = 28;

pub(super) fn build_request(
    request: &NeighborRequest,
    source: Ipv4Addr,
    target: Ipv4Addr,
) -> Bytes {
    let destination = MacAddress([0xff; 6]);
    let mut frame = ethernet::prefix(
        destination,
        request.interface_mac,
        &request.vlan_tags,
        ethernet::ETHERTYPE_ARP,
    );
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&[6, 4]);
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&request.interface_mac.0);
    frame.extend_from_slice(&source.octets());
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&target.octets());
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "vlan_tags is capped at MAX_VLAN_TAGS, so the padded length is a small sum"
    )]
    let padded_length =
        ethernet::MINIMUM_WITHOUT_FCS + request.vlan_tags.len() * ethernet::VLAN_HEADER_LENGTH;
    frame.resize(padded_length, 0);
    Bytes::from(frame)
}

pub(super) fn match_response(
    request: &NeighborRequest,
    source: Ipv4Addr,
    target: Ipv4Addr,
    ethernet: View<'_>,
) -> Option<MacAddress> {
    let arp = ethernet.payload.first_chunk::<PAYLOAD_LENGTH>()?;
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
        || !ethernet::is_unicast_mac(sender_mac)
    {
        return None;
    }
    Some(sender_mac)
}
