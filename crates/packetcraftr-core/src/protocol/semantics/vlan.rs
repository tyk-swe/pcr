// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::{Constraint, Error};
use super::path::outer_scope_len;
use crate::layer::Layer;
use crate::packet::Packet;
use crate::packet::VlanTag;
use crate::protocol::identity;

/// Outermost-first VLAN tags on the directly transmitted packet.
pub fn vlan_tags(packet: &Packet) -> Result<Vec<VlanTag>, Error> {
    packet
        .iter()
        .take(outer_scope_len(packet))
        .filter_map(|layer| {
            let tag = identity::vlan_tag(layer)?;
            Some(checked_tag(layer, tag))
        })
        .collect()
}

fn checked_tag(layer: &dyn Layer, tag: VlanTag) -> Result<VlanTag, Error> {
    if tag.priority > 7 {
        return Err(Error::field(
            layer.protocol_id(),
            "priority",
            Constraint::PriorityAtMost7,
        ));
    }
    if tag.vlan_id > 4095 {
        return Err(Error::field(
            layer.protocol_id(),
            "vlan_id",
            Constraint::VlanIdAtMost4095,
        ));
    }
    Ok(tag)
}
