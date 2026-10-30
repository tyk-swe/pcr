// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IEEE 802.1AX LACP version 1. Marker and other Slow Protocols remain opaque.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lacp {
    pub actor_system_priority: u16,
    pub actor_system: [u8; 6],
    pub actor_key: u16,
    pub actor_port_priority: u16,
    pub actor_port: u16,
    pub actor_state: u8,
    pub partner_system_priority: u16,
    pub partner_system: [u8; 6],
    pub partner_key: u16,
    pub partner_port_priority: u16,
    pub partner_port: u16,
    pub partner_state: u8,
    pub collector_delay: u16,
    pub reserved: Bytes,
}
impl Default for Lacp {
    fn default() -> Self {
        Self {
            actor_system_priority: 32768,
            actor_system: [0; 6],
            actor_key: 0,
            actor_port_priority: 32768,
            actor_port: 1,
            actor_state: 0,
            partner_system_priority: 32768,
            partner_system: [0; 6],
            partner_key: 0,
            partner_port_priority: 32768,
            partner_port: 1,
            partner_state: 0,
            collector_delay: 0,
            reserved: Bytes::from(vec![0; 68]),
        }
    }
}
crate::reflective_layer! {
 fn lacp_schema() => { protocol: crate::layer::Id::new("lacp"), name: "Lacp" }
 impl Lacp {
    "actor_system_priority" => { kind: Unsigned, derived: false, required: false, description: "actor system priority", reflect: actor_system_priority },
    "actor_system" => { kind: Mac, derived: false, required: false, description: "actor system", reflect: actor_system },
    "actor_key" => { kind: Unsigned, derived: false, required: false, description: "actor key", reflect: actor_key },
    "actor_port_priority" => { kind: Unsigned, derived: false, required: false, description: "actor port priority", reflect: actor_port_priority },
    "actor_port" => { kind: Unsigned, derived: false, required: false, description: "actor port", reflect: actor_port },
    "actor_state" => { kind: Unsigned, derived: false, required: false, description: "actor state", reflect: actor_state },
    "partner_system_priority" => { kind: Unsigned, derived: false, required: false, description: "partner system priority", reflect: partner_system_priority },
    "partner_system" => { kind: Mac, derived: false, required: false, description: "partner system", reflect: partner_system },
    "partner_key" => { kind: Unsigned, derived: false, required: false, description: "partner key", reflect: partner_key },
    "partner_port_priority" => { kind: Unsigned, derived: false, required: false, description: "partner port priority", reflect: partner_port_priority },
    "partner_port" => { kind: Unsigned, derived: false, required: false, description: "partner port", reflect: partner_port },
    "partner_state" => { kind: Unsigned, derived: false, required: false, description: "partner state", reflect: partner_state },
    "collector_delay" => { kind: Unsigned, derived: false, required: false, description: "collector delay", reflect: collector_delay },
    "reserved" => { kind: Bytes, derived: false, required: false, description: "Actor, partner, collector and trailing reserved bytes", reflect: reserved },
 }
}
fn lacp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if 6 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "actor_system_priority",
            range: crate::layout::ByteRange::new(4, 6),
        });
    }
    if 12 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "actor_system",
            range: crate::layout::ByteRange::new(6, 12),
        });
    }
    if 14 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "actor_key",
            range: crate::layout::ByteRange::new(12, 14),
        });
    }
    if 16 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "actor_port_priority",
            range: crate::layout::ByteRange::new(14, 16),
        });
    }
    if 18 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "actor_port",
            range: crate::layout::ByteRange::new(16, 18),
        });
    }
    if 19 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "actor_state",
            range: crate::layout::ByteRange::new(18, 19),
        });
    }
    if 26 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "partner_system_priority",
            range: crate::layout::ByteRange::new(24, 26),
        });
    }
    if 32 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "partner_system",
            range: crate::layout::ByteRange::new(26, 32),
        });
    }
    if 34 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "partner_key",
            range: crate::layout::ByteRange::new(32, 34),
        });
    }
    if 36 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "partner_port_priority",
            range: crate::layout::ByteRange::new(34, 36),
        });
    }
    if 38 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "partner_port",
            range: crate::layout::ByteRange::new(36, 38),
        });
    }
    if 39 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "partner_state",
            range: crate::layout::ByteRange::new(38, 39),
        });
    }
    if 46 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "collector_delay",
            range: crate::layout::ByteRange::new(44, 46),
        });
    }
    fields
}
message_codec!(LacpCodec, Lacp, lacp_schema, lacp_layout_wire);

const NAME: &str = "lacp";
impl Lacp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.reserved.len() != 68 {
            return Err(invalid(NAME, "LACP requires 68 reserved bytes"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.put(&[1, 1])?;
        w.put(&[1, 20])?;
        w.u16(self.actor_system_priority)?;
        w.put(&self.actor_system)?;
        w.u16(self.actor_key)?;
        w.u16(self.actor_port_priority)?;
        w.u16(self.actor_port)?;
        w.u8(self.actor_state)?;
        w.put(&self.reserved[0..3])?;
        w.put(&[2, 20])?;
        w.u16(self.partner_system_priority)?;
        w.put(&self.partner_system)?;
        w.u16(self.partner_key)?;
        w.u16(self.partner_port_priority)?;
        w.u16(self.partner_port)?;
        w.u8(self.partner_state)?;
        w.put(&self.reserved[3..6])?;
        w.put(&[3, 16])?;
        w.u16(self.collector_delay)?;
        w.put(&self.reserved[6..18])?;
        w.put(&[0, 0])?;
        w.put(&self.reserved[18..])?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        if r.take(2)? != [1, 1] {
            return Err(unsupported(NAME, "not LACP version 1"));
        }
        let mut s = Self::default();
        let mut reserved = Vec::new();
        if r.take(2)? != [1, 20] {
            return Err(invalid(NAME, "invalid actor TLV"));
        }
        s.actor_system_priority = r.u16()?;
        s.actor_system = r.take(6)?.try_into().unwrap();
        s.actor_key = r.u16()?;
        s.actor_port_priority = r.u16()?;
        s.actor_port = r.u16()?;
        s.actor_state = r.u8()?;
        reserved.extend_from_slice(r.take(3)?);
        if r.take(2)? != [2, 20] {
            return Err(invalid(NAME, "invalid partner TLV"));
        }
        s.partner_system_priority = r.u16()?;
        s.partner_system = r.take(6)?.try_into().unwrap();
        s.partner_key = r.u16()?;
        s.partner_port_priority = r.u16()?;
        s.partner_port = r.u16()?;
        s.partner_state = r.u8()?;
        reserved.extend_from_slice(r.take(3)?);
        if r.take(2)? != [3, 16] {
            return Err(invalid(NAME, "invalid collector TLV"));
        }
        s.collector_delay = r.u16()?;
        reserved.extend_from_slice(r.take(12)?);
        if r.take(2)? != [0, 0] {
            return Err(invalid(NAME, "invalid terminator"));
        }
        reserved.extend_from_slice(r.take(50)?);
        r.finish()?;
        s.reserved = reserved.into();
        Ok(s)
    }
}
