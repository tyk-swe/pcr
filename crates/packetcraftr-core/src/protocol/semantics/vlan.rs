// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::{Constraint, Error};
use super::path::outer_scope_len;
use crate::layer::Layer;
use crate::packet::Packet;
use crate::packet::link::{VlanKind, VlanTag};
use crate::protocol::link::{Vlan, Vlan8021ad};

/// Outermost-first VLAN tags on the directly transmitted packet.
pub fn vlan_tags(packet: &Packet) -> Result<Vec<VlanTag>, Error> {
    packet
        .iter()
        .take(outer_scope_len(packet))
        .filter_map(|layer| {
            let (kind, priority, drop_eligible, vlan_id) =
                if let Some(tag) = layer.downcast_ref::<Vlan>() {
                    (
                        VlanKind::Ieee8021Q,
                        tag.priority,
                        tag.drop_eligible,
                        tag.vlan_id,
                    )
                } else {
                    let tag = layer.downcast_ref::<Vlan8021ad>()?;
                    (
                        VlanKind::Ieee8021Ad,
                        tag.priority,
                        tag.drop_eligible,
                        tag.vlan_id,
                    )
                };
            Some(checked_tag(
                layer,
                VlanTag {
                    kind,
                    priority,
                    drop_eligible,
                    vlan_id,
                },
            ))
        })
        .collect()
}

/// Checks the ranges a directly constructed tag can exceed.
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
