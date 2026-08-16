// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ethernet envelope and bounded VLAN-stack handling for neighbor traffic.

use crate::{
    link::MacAddress,
    neighbor::{
        MAX_VLAN_TAGS as MAX_NEIGHBOR_VLAN_TAGS, VlanKind as NeighborVlanKind,
        VlanTag as NeighborVlanTag,
    },
};

pub(super) const HEADER_LENGTH: usize = 14;
pub(super) const MINIMUM_WITHOUT_FCS: usize = 60;
pub(super) const VLAN_HEADER_LENGTH: usize = 4;
pub(super) const ETHERTYPE_ARP: u16 = 0x0806;
pub(super) const ETHERTYPE_IPV6: u16 = 0x86dd;
pub(super) const ETHERTYPE_VLAN: u16 = 0x8100;
pub(super) const ETHERTYPE_SERVICE_VLAN: u16 = 0x88a8;

pub(super) struct View<'a> {
    pub(super) destination: MacAddress,
    pub(super) source: MacAddress,
    pub(super) vlan_tags: Vec<NeighborVlanTag>,
    pub(super) ether_type: u16,
    pub(super) payload: &'a [u8],
}

pub(super) fn prefix(
    destination: MacAddress,
    source: MacAddress,
    tags: &[NeighborVlanTag],
    payload_type: u16,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(
        HEADER_LENGTH + tags.len() * VLAN_HEADER_LENGTH + super::arp::PAYLOAD_LENGTH,
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

pub(super) fn parse(bytes: &[u8]) -> Option<View<'_>> {
    if bytes.len() < HEADER_LENGTH {
        return None;
    }
    let mut destination = [0; 6];
    destination.copy_from_slice(&bytes[..6]);
    let mut source = [0; 6];
    source.copy_from_slice(&bytes[6..12]);
    let mut ether_type = u16::from_be_bytes([bytes[12], bytes[13]]);
    let mut offset = HEADER_LENGTH;
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
    Some(View {
        destination: MacAddress(destination),
        source: MacAddress(source),
        vlan_tags,
        ether_type,
        payload: &bytes[offset..],
    })
}

pub(super) fn is_unicast_mac(address: MacAddress) -> bool {
    address.0 != [0; 6] && address.0 != [0xff; 6] && address.0[0] & 1 == 0
}
