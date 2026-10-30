// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! OSPF version 3 packet types 1-5. LSA bodies remain opaque.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use super::ospf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ospfv3 {
    pub packet_type: u8,
    pub router_id: u32,
    pub area_id: u32,
    pub checksum: field::WireValue<u16>,
    pub instance_id: u8,
    pub reserved: u8,
    pub interface_id: u32,
    pub hello_interval: u16,
    pub options: u32,
    pub priority: u8,
    pub dead_interval: u16,
    pub designated_router: u32,
    pub backup_router: u32,
    pub neighbors: Records,
    pub lsas: Records,
    pub data: Bytes,
}
impl Default for Ospfv3 {
    fn default() -> Self {
        Self {
            packet_type: 1,
            router_id: 0,
            area_id: 0,
            checksum: field::WireValue::Auto,
            instance_id: 0,
            reserved: 0,
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
 fn ospfv3_schema() => { protocol: crate::layer::Id::new("ospfv3"), name: "Ospfv3" }
 impl Ospfv3 {
    "packet_type" => { kind: Unsigned, derived: false, required: false, description: "packet type", reflect: packet_type },
    "router_id" => { kind: Unsigned, derived: false, required: false, description: "router id", reflect: router_id },
    "area_id" => { kind: Unsigned, derived: false, required: false, description: "area id", reflect: area_id },
    "checksum" => { kind: Unsigned, derived: true, required: false, description: "checksum", reflect: checksum },
    "instance_id" => { kind: Unsigned, derived: false, required: false, description: "instance id", reflect: instance_id },
    "reserved" => { kind: Unsigned, derived: false, required: false, description: "reserved", reflect: reserved },
    "interface_id" => { kind: Unsigned, derived: false, required: false, description: "interface id", reflect: interface_id },
    "hello_interval" => { kind: Unsigned, derived: false, required: false, description: "hello interval", reflect: hello_interval },
    "options" => { kind: Unsigned, derived: false, required: false, description: "options", reflect_bounded: options, 0xff_ffff_u64 },
    "priority" => { kind: Unsigned, derived: false, required: false, description: "priority", reflect: priority },
    "dead_interval" => { kind: Unsigned, derived: false, required: false, description: "dead interval", reflect: dead_interval },
    "designated_router" => { kind: Unsigned, derived: false, required: false, description: "designated router", reflect: designated_router },
    "backup_router" => { kind: Unsigned, derived: false, required: false, description: "backup router", reflect: backup_router },
    "neighbors" => { kind: List, derived: false, required: false, description: "Hello neighbor router IDs", children: ospf::NEIGHBORS, reflect: neighbors },
    "lsas" => { kind: List, derived: false, required: false, description: "LSA header and opaque body", children: ospf::LSAS, reflect: lsas },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
}
message_codec!(Ospfv3Codec, Ospfv3, ospfv3_schema, ospf::header_layout);

const NAME: &str = "ospfv3";
const VERSION: u8 = 3;
const DD_MINIMUM: usize = 12;
impl Ospfv3 {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut p = Writer::new(NAME, c.remaining_packet_bytes);
        match self.packet_type {
            1 => {
                p.u32(self.interface_id)?;
                p.u8(self.priority)?;
                if self.options > 0xff_ffff {
                    return Err(invalid(NAME, "options exceed 24 bits"));
                }
                p.put(&self.options.to_be_bytes()[1..])?;
                p.u16(self.hello_interval)?;
                p.u16(self.dead_interval)?;
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
        let len = p.bytes.len() + 16;
        w.u16(u16::try_from(len).map_err(|_| invalid(NAME, "packet too long"))?)?;
        w.u32(self.router_id)?;
        w.u32(self.area_id)?;
        w.u16(0)?;
        w.u8(self.instance_id)?;
        w.u8(self.reserved)?;
        w.put(&p.bytes)?;
        let expected =
            transport_checksum_parts(NAME, super::resolve_envelope(NAME, c)?, 89, &[&w.bytes])?;
        let sum = crate::protocol::message::checksum_value(NAME, &self.checksum, expected, c)?;
        w.bytes[12..14].copy_from_slice(&sum.to_be_bytes());
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
        if len != b.len() {
            return Err(invalid(NAME, "packet length mismatch"));
        }
        s.router_id = r.u32()?;
        s.area_id = r.u32()?;
        s.checksum = field::WireValue::Exact(r.u16()?);
        s.instance_id = r.u8()?;
        s.reserved = r.u8()?;
        let valid = c
            .network
            .map(|net| transport_checksum_parts(NAME, net, 89, &[&b]))
            .transpose()?
            .is_none_or(|sum| sum == 0);
        if !valid {
            return Err(invalid(NAME, "OSPF checksum mismatch"));
        }
        match s.packet_type {
            1 => {
                s.interface_id = r.u32()?;
                s.priority = r.u8()?;
                let opts = r.take(3)?;
                s.options = u32::from_be_bytes([0, opts[0], opts[1], opts[2]]);
                s.hello_interval = r.u16()?;
                s.dead_interval = r.u16()?;
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
