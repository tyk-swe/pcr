// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! OSPF version 2 packet types 1-5. LSA bodies and authentication bytes remain opaque.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use super::ospf;

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
    pub network_mask: u32,
    pub hello_interval: u16,
    pub options: u8,
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
            network_mask: 0,
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
    "network_mask" => { kind: Unsigned, derived: false, required: false, description: "network mask", reflect: network_mask },
    "hello_interval" => { kind: Unsigned, derived: false, required: false, description: "hello interval", reflect: hello_interval },
    "options" => { kind: Unsigned, derived: false, required: false, description: "options", reflect: options },
    "priority" => { kind: Unsigned, derived: false, required: false, description: "priority", reflect: priority },
    "dead_interval" => { kind: Unsigned, derived: false, required: false, description: "dead interval", reflect: dead_interval },
    "designated_router" => { kind: Unsigned, derived: false, required: false, description: "designated router", reflect: designated_router },
    "backup_router" => { kind: Unsigned, derived: false, required: false, description: "backup router", reflect: backup_router },
    "neighbors" => { kind: List, derived: false, required: false, description: "Hello neighbor router IDs", children: ospf::NEIGHBORS, reflect: neighbors },
    "lsas" => { kind: List, derived: false, required: false, description: "LSA header and opaque body", children: ospf::LSAS, reflect: lsas },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
}
fn ospfv2_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = ospf::header_layout(b);
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
const DD_MINIMUM: usize = 8;
impl Ospfv2 {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut p = Writer::new(NAME, c.remaining_packet_bytes);
        match self.packet_type {
            1 => {
                p.u32(self.network_mask)?;
                p.u16(self.hello_interval)?;
                p.u8(self.options)?;
                p.u8(self.priority)?;
                p.u32(self.dead_interval)?;
                p.u32(self.designated_router)?;
                p.u32(self.backup_router)?;
                ospf::encode_neighbors(&mut p, &self.neighbors, NAME)?;
            }
            4 | 5 => ospf::encode_lsas(&mut p, &self.lsas, self.packet_type, NAME)?,
            2 | 3 => p.put(&self.data)?,
            _ => return Err(unsupported(NAME, "unknown packet type")),
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(VERSION)?;
        w.u8(self.packet_type)?;
        let len = p.bytes.len() + 24;
        w.u16(u16::try_from(len).map_err(|_| invalid(NAME, "packet too long"))?)?;
        w.u32(self.router_id)?;
        w.u32(self.area_id)?;
        w.u16(0)?;
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
        w.put(&p.bytes)?;
        let expected = if self.auth_type == 2 {
            0
        } else {
            checksum_parts(&[&w.bytes[..16], &w.bytes[24..]])
        };
        let sum = crate::protocol::message::checksum_value(NAME, &self.checksum, expected, c)?;
        w.bytes[12..14].copy_from_slice(&sum.to_be_bytes());
        w.put(&self.auth_trailer)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
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
        s.auth_type = r.u16()?;
        s.auth_data = Bytes::copy_from_slice(r.take(8)?);
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
        let valid = s.auth_type == 2 || checksum_parts(&[&b[..16], &b[24..len]]) == 0;
        if !valid {
            return Err(invalid(NAME, "OSPF checksum mismatch"));
        }
        match s.packet_type {
            1 => {
                s.network_mask = r.u32()?;
                s.hello_interval = r.u16()?;
                s.options = r.u8()?;
                s.priority = r.u8()?;
                s.dead_interval = r.u32()?;
                s.designated_router = r.u32()?;
                s.backup_router = r.u32()?;
                s.neighbors = ospf::parse_neighbors(&mut r, NAME)?;
            }
            4 | 5 => s.lsas = ospf::parse_lsas(&mut r, s.packet_type, NAME)?,
            2 | 3 => s.data = ospf::parse_opaque_body(&mut r, s.packet_type, DD_MINIMUM, NAME)?,
            _ => return Err(unsupported(NAME, "unsupported packet type")),
        }
        r.finish()?;
        Ok(s)
    }
}
