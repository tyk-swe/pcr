// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! OSPF version 2 packet types 1-5. LSA bodies and authentication bytes remain opaque.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const NEIGHBORS: &[crate::layer::FieldSchema] = &[member("router_id", field::Kind::Unsigned, &[])];
const LSAS: &[crate::layer::FieldSchema] = &[
    member("header", field::Kind::Bytes, &[]),
    member("body", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ospfv2 {
    pub packet_type: u8,
    pub router_id: u32,
    pub area_id: u32,
    pub checksum: field::WireValue<u16>,
    pub auth_type: u16,
    pub auth_data: Bytes,
    /// Supplied authentication digest; excluded from the OSPF Packet Length.
    pub auth_trailer: Bytes,
    pub instance_id: u8,
    pub reserved: u8,
    pub network_mask: u32,
    pub interface_id: u32,
    pub hello_interval: u16,
    pub options: u32,
    pub priority: u8,
    pub dead_interval: u32,
    pub designated_router: u32,
    pub backup_router: u32,
    pub neighbors: Records,
    pub lsas: Records,
    pub data: Bytes,
}
impl Default for Ospfv2 {
    fn default() -> Self {
        Self {
            packet_type: 1,
            router_id: 0,
            area_id: 0,
            checksum: field::WireValue::Auto,
            auth_type: 0,
            auth_data: Bytes::from_static(&[0; 8]),
            auth_trailer: Bytes::new(),
            instance_id: 0,
            reserved: 0,
            network_mask: 0,
            interface_id: 0,
            hello_interval: 10,
            options: 0,
            priority: 1,
            dead_interval: 40,
            designated_router: 0,
            backup_router: 0,
            neighbors: Records::default(),
            lsas: Records::default(),
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn ospfv2_schema() => { protocol: crate::layer::Id::new("ospfv2"), name: "Ospfv2" }
 impl Ospfv2 {
    "packet_type" => { kind: Unsigned, derived: false, required: false, description: "packet type", reflect: packet_type },
    "router_id" => { kind: Unsigned, derived: false, required: false, description: "router id", reflect: router_id },
    "area_id" => { kind: Unsigned, derived: false, required: false, description: "area id", reflect: area_id },
    "checksum" => { kind: Unsigned, derived: true, required: false, description: "checksum", reflect: checksum },
    "auth_type" => { kind: Unsigned, derived: false, required: false, description: "auth type", reflect: auth_type },
    "auth_data" => { kind: Bytes, derived: false, required: false, description: "auth data", reflect: auth_data },
    "auth_trailer" => { kind: Bytes, derived: false, required: false, description: "Opaque cryptographic digest outside the OSPF Packet Length", reflect: auth_trailer },
    "instance_id" => { kind: Unsigned, derived: false, required: false, description: "instance id", reflect: instance_id },
    "reserved" => { kind: Unsigned, derived: false, required: false, description: "reserved", reflect: reserved },
    "network_mask" => { kind: Unsigned, derived: false, required: false, description: "network mask", reflect: network_mask },
    "interface_id" => { kind: Unsigned, derived: false, required: false, description: "interface id", reflect: interface_id },
    "hello_interval" => { kind: Unsigned, derived: false, required: false, description: "hello interval", reflect: hello_interval },
    "options" => { kind: Unsigned, derived: false, required: false, description: "options", reflect: options },
    "priority" => { kind: Unsigned, derived: false, required: false, description: "priority", reflect: priority },
    "dead_interval" => { kind: Unsigned, derived: false, required: false, description: "dead interval", reflect: dead_interval },
    "designated_router" => { kind: Unsigned, derived: false, required: false, description: "designated router", reflect: designated_router },
    "backup_router" => { kind: Unsigned, derived: false, required: false, description: "backup router", reflect: backup_router },
    "neighbors" => { kind: List, derived: false, required: false, description: "Hello neighbor router IDs", children: NEIGHBORS, reflect: neighbors },
    "lsas" => { kind: List, derived: false, required: false, description: "LSA header and opaque body", children: LSAS, reflect: lsas },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
 layout fn ospfv2_layout();
}
fn ospfv2_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = ospfv2_layout();
    let mut fields = Vec::new();
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "packet_type",
            range: crate::layout::ByteRange::new(1, 2),
        });
    }
    if 8 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "router_id",
            range: crate::layout::ByteRange::new(4, 8),
        });
    }
    if 12 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "area_id",
            range: crate::layout::ByteRange::new(8, 12),
        });
    }
    if 14 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "checksum",
            range: crate::layout::ByteRange::new(12, 14),
        });
    }
    if b.len() >= 24 && b[14..16] == [0, 2] {
        let start = usize::from(u16::from_be_bytes([b[2], b[3]]));
        if start <= b.len() {
            fields.push(crate::layout::FieldLayout {
                name: "auth_trailer",
                range: crate::layout::ByteRange::new(start, b.len()),
            });
        }
    }
    fields
}
message_codec!(Ospfv2Codec, Ospfv2, ospfv2_schema, ospfv2_layout_wire);

const NAME: &str = "ospfv2";
const VERSION: u8 = 2;
impl Ospfv2 {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut p = Writer::new(NAME, c.remaining_packet_bytes);
        match self.packet_type {
            1 => {
                if VERSION == 2 {
                    p.u32(self.network_mask)?;
                    p.u16(self.hello_interval)?;
                    p.u8(u8::try_from(self.options)
                        .map_err(|_| invalid(NAME, "options exceed one byte"))?)?;
                    p.u8(self.priority)?;
                    p.u32(self.dead_interval)?;
                } else {
                    p.u32(self.interface_id)?;
                    p.u8(self.priority)?;
                    if self.options > 0xffffff {
                        return Err(invalid(NAME, "options exceed 24 bits"));
                    }
                    p.put(&self.options.to_be_bytes()[1..])?;
                    p.u16(self.hello_interval)?;
                    p.u16(
                        u16::try_from(self.dead_interval)
                            .map_err(|_| invalid(NAME, "dead interval overflow"))?,
                    )?;
                }
                p.u32(self.designated_router)?;
                p.u32(self.backup_router)?;
                for r in &self.neighbors.0 {
                    p.u32(
                        u32::try_from(number(r, "router_id", NAME)?)
                            .map_err(|_| invalid(NAME, "router ID overflow"))?,
                    )?;
                }
            }
            4 | 5 => {
                if self.packet_type == 4 {
                    p.u32(
                        u32::try_from(self.lsas.0.len())
                            .map_err(|_| invalid(NAME, "too many LSAs"))?,
                    )?;
                }
                for r in &self.lsas.0 {
                    let h = data(r, "header", NAME)?;
                    let b = data(r, "body", NAME)?;
                    if h.len() != 20
                        || self.packet_type == 5 && !b.is_empty()
                        || self.packet_type == 4
                            && usize::from(u16::from_be_bytes([h[18], h[19]])) != 20 + b.len()
                    {
                        return Err(invalid(NAME, "invalid LSA envelope"));
                    }
                    p.put(h)?;
                    p.put(b)?;
                }
            }
            2 | 3 => p.put(&self.data)?,
            _ => return Err(unsupported(NAME, "unknown packet type")),
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(VERSION)?;
        w.u8(self.packet_type)?;
        let len = p.bytes.len() + if VERSION == 2 { 24 } else { 16 };
        w.u16(u16::try_from(len).map_err(|_| invalid(NAME, "packet too long"))?)?;
        w.u32(self.router_id)?;
        w.u32(self.area_id)?;
        w.u16(0)?;
        if VERSION == 2 {
            if self.auth_data.len() != 8 {
                return Err(invalid(NAME, "authentication field requires eight bytes"));
            }
            let trailer_len = if self.auth_type == 2 {
                usize::from(self.auth_data[3])
            } else {
                0
            };
            if self.auth_trailer.len() != trailer_len {
                return Err(invalid(NAME, "authentication digest length mismatch"));
            }
            w.u16(self.auth_type)?;
            w.put(&self.auth_data)?;
        } else {
            w.u8(self.instance_id)?;
            w.u8(self.reserved)?;
        }
        w.put(&p.bytes)?;
        let expected = if VERSION == 2 {
            if self.auth_type == 2 {
                0
            } else {
                checksum_parts(&[&w.bytes[..16], &w.bytes[24..]])
            }
        } else {
            transport_checksum(NAME, super::resolve_envelope(NAME, c)?, 89, &w.bytes)?
        };
        let sum = crate::protocol::message::checksum_value(NAME, &self.checksum, expected, c)?;
        w.bytes[12..14].copy_from_slice(&sum.to_be_bytes());
        w.put(&self.auth_trailer)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, c: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        if r.u8()? != VERSION {
            return Err(unsupported(NAME, "wrong OSPF version"));
        }
        let mut s = Self {
            packet_type: r.u8()?,
            ..Self::default()
        };
        let len = r.u16()? as usize;
        if len < 24 || len > b.len() {
            return Err(invalid(NAME, "packet length mismatch"));
        }
        s.router_id = r.u32()?;
        s.area_id = r.u32()?;
        s.checksum = field::WireValue::Exact(r.u16()?);
        if VERSION == 2 {
            s.auth_type = r.u16()?;
            s.auth_data = Bytes::copy_from_slice(r.take(8)?);
        } else {
            s.instance_id = r.u8()?;
            s.reserved = r.u8()?;
        }
        let trailer_len = if s.auth_type == 2 {
            usize::from(s.auth_data[3])
        } else {
            0
        };
        if len.checked_add(trailer_len) != Some(b.len()) {
            return Err(invalid(
                NAME,
                "packet or authentication digest length mismatch",
            ));
        }
        s.auth_trailer = b.slice(len..);
        r.bytes = &b[..len];
        let valid = if VERSION == 2 {
            s.auth_type == 2 || checksum_parts(&[&b[..16], &b[24..len]]) == 0
        } else {
            c.network
                .map(|net| transport_checksum(NAME, net, 89, &b))
                .transpose()?
                .is_none_or(|sum| sum == 0)
        };
        if !valid {
            return Err(invalid(NAME, "OSPF checksum mismatch"));
        }
        match s.packet_type {
            1 => {
                if VERSION == 2 {
                    s.network_mask = r.u32()?;
                    s.hello_interval = r.u16()?;
                    s.options = u32::from(r.u8()?);
                    s.priority = r.u8()?;
                    s.dead_interval = r.u32()?;
                } else {
                    s.interface_id = r.u32()?;
                    s.priority = r.u8()?;
                    let opts = r.take(3)?;
                    s.options = u32::from_be_bytes([0, opts[0], opts[1], opts[2]]);
                    s.hello_interval = r.u16()?;
                    s.dead_interval = u32::from(r.u16()?);
                }
                s.designated_router = r.u32()?;
                s.backup_router = r.u32()?;
                while r.left() > 0 {
                    if s.neighbors.0.len() == MAX_RECORDS {
                        return Err(invalid(NAME, "too many neighbors"));
                    }
                    s.neighbors.0.push(record([("router_id", r.u32()?.into())]));
                }
            }
            4 | 5 => {
                let count = if s.packet_type == 4 {
                    r.u32()? as usize
                } else {
                    r.left() / 20
                };
                if count > MAX_RECORDS {
                    return Err(invalid(NAME, "too many LSAs"));
                }
                for _ in 0..count {
                    let h = r.take(20)?;
                    let len = usize::from(u16::from_be_bytes([h[18], h[19]]));
                    if len < 20 {
                        return Err(invalid(NAME, "short LSA"));
                    }
                    let body = if s.packet_type == 4 {
                        r.take(len - 20)?
                    } else {
                        &[]
                    };
                    s.lsas.0.push(record([
                        ("header", Bytes::copy_from_slice(h).into()),
                        ("body", Bytes::copy_from_slice(body).into()),
                    ]));
                }
            }
            2 => {
                let min = if VERSION == 2 { 8 } else { 12 };
                if r.left() < min || !(r.left() - min).is_multiple_of(20) {
                    return Err(invalid(NAME, "invalid database description"));
                }
                s.data = Bytes::copy_from_slice(r.rest());
            }
            3 => {
                if !r.left().is_multiple_of(12) {
                    return Err(invalid(NAME, "invalid link-state request"));
                }
                s.data = Bytes::copy_from_slice(r.rest());
            }
            _ => return Err(unsupported(NAME, "unsupported packet type")),
        }
        r.finish()?;
        Ok(s)
    }
}
