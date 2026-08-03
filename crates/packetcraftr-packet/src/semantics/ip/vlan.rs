// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Directly transmitted VLAN metadata interpretation.

use super::super::{BuiltinProtocol, FieldValue, Packet};
use super::error::SemanticError;
use super::path::{outer_scope_len, required_u8_field};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VlanKind {
    Ieee8021Q,
    Ieee8021Ad,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VlanMetadata {
    pub kind: VlanKind,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

/// VLAN tags on the directly transmitted packet, outermost first. Tags inside
/// an encapsulated frame belong to the tunneled network, not to the link this
/// packet leaves on.
pub fn vlan_metadata(packet: &Packet) -> Result<Vec<VlanMetadata>, SemanticError> {
    packet
        .iter()
        .take(outer_scope_len(packet))
        .filter_map(|layer| match BuiltinProtocol::of(layer) {
            Some(BuiltinProtocol::Vlan) => Some((layer, VlanKind::Ieee8021Q)),
            Some(BuiltinProtocol::Vlan8021ad) => Some((layer, VlanKind::Ieee8021Ad)),
            _ => None,
        })
        .map(|(layer, kind)| {
            let priority = required_u8_field(layer, "priority")?;
            if priority > 7 {
                return Err(SemanticError::field(
                    layer.protocol_id(),
                    "priority",
                    "is outside 0..=7",
                ));
            }
            let drop_eligible = match layer.field("drop_eligible") {
                Some(FieldValue::Bool(value)) => value,
                Some(_) => {
                    return Err(SemanticError::field(
                        layer.protocol_id(),
                        "drop_eligible",
                        "is not boolean",
                    ));
                }
                None => {
                    return Err(SemanticError::field(
                        layer.protocol_id(),
                        "drop_eligible",
                        "is missing",
                    ));
                }
            };
            let vlan_id = match layer.field("vlan_id") {
                Some(FieldValue::Unsigned(value)) => u16::try_from(value)
                    .ok()
                    .filter(|value| *value <= 4095)
                    .ok_or_else(|| {
                        SemanticError::field(layer.protocol_id(), "vlan_id", "is outside 0..=4095")
                    })?,
                Some(_) => {
                    return Err(SemanticError::field(
                        layer.protocol_id(),
                        "vlan_id",
                        "is not unsigned",
                    ));
                }
                None => {
                    return Err(SemanticError::field(
                        layer.protocol_id(),
                        "vlan_id",
                        "is missing",
                    ));
                }
            };
            Ok(VlanMetadata {
                kind,
                priority,
                drop_eligible,
                vlan_id,
            })
        })
        .collect()
}
