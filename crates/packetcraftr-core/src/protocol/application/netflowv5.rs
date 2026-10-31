// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! NetFlow version 5 fixed 48-byte flow records, with reserved bytes retained.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const FLOW_FIELDS: &[crate::layer::FieldSchema] = &[
    member("source", field::Kind::Ipv4, &[]),
    member("destination", field::Kind::Ipv4, &[]),
    member("next_hop", field::Kind::Ipv4, &[]),
    member("input", field::Kind::Unsigned, &[]),
    member("output", field::Kind::Unsigned, &[]),
    member("packets", field::Kind::Unsigned, &[]),
    member("octets", field::Kind::Unsigned, &[]),
    member("first", field::Kind::Unsigned, &[]),
    member("last", field::Kind::Unsigned, &[]),
    member("source_port", field::Kind::Unsigned, &[]),
    member("destination_port", field::Kind::Unsigned, &[]),
    member("pad1", field::Kind::Unsigned, &[]),
    member("tcp_flags", field::Kind::Unsigned, &[]),
    member("protocol", field::Kind::Unsigned, &[]),
    member("tos", field::Kind::Unsigned, &[]),
    member("source_as", field::Kind::Unsigned, &[]),
    member("destination_as", field::Kind::Unsigned, &[]),
    member("source_mask", field::Kind::Unsigned, &[]),
    member("destination_mask", field::Kind::Unsigned, &[]),
    member("pad2", field::Kind::Unsigned, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Netflowv5 {
    pub uptime: u32,
    pub unix_seconds: u32,
    pub unix_nanoseconds: u32,
    pub sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub sampling: u16,
    pub records: Records,
}
crate::reflective_layer! {
 fn netflowv5_schema() => { protocol: crate::layer::Id::new("netflowv5"), name: "Netflowv5" }
 impl Netflowv5 {
    "uptime" => { kind: Unsigned, derived: false, required: false, description: "uptime", reflect: uptime },
    "unix_seconds" => { kind: Unsigned, derived: false, required: false, description: "unix seconds", reflect: unix_seconds },
    "unix_nanoseconds" => { kind: Unsigned, derived: false, required: false, description: "unix nanoseconds", reflect: unix_nanoseconds },
    "sequence" => { kind: Unsigned, derived: false, required: false, description: "sequence", reflect: sequence },
    "engine_type" => { kind: Unsigned, derived: false, required: false, description: "engine type", reflect: engine_type },
    "engine_id" => { kind: Unsigned, derived: false, required: false, description: "engine id", reflect: engine_id },
    "sampling" => { kind: Unsigned, derived: false, required: false, description: "sampling", reflect: sampling },
    "records" => { kind: List, derived: false, required: false, description: "Fixed-width NetFlow v5 flow records", children: FLOW_FIELDS, reflect: records },
 }
}
fn netflowv5_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if 8 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "uptime",
            range: crate::layout::ByteRange::new(4, 8),
        });
    }
    if 12 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "unix_seconds",
            range: crate::layout::ByteRange::new(8, 12),
        });
    }
    if 16 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "unix_nanoseconds",
            range: crate::layout::ByteRange::new(12, 16),
        });
    }
    if 20 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "sequence",
            range: crate::layout::ByteRange::new(16, 20),
        });
    }
    if 21 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "engine_type",
            range: crate::layout::ByteRange::new(20, 21),
        });
    }
    if 22 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "engine_id",
            range: crate::layout::ByteRange::new(21, 22),
        });
    }
    if 24 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "sampling",
            range: crate::layout::ByteRange::new(22, 24),
        });
    }
    if b.len() <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "records",
            range: crate::layout::ByteRange::new(24, b.len()),
        });
    }
    fields
}
message_codec!(
    Netflowv5Codec,
    Netflowv5,
    netflowv5_schema,
    netflowv5_layout_wire
);

const NAME: &str = "netflowv5";
impl Netflowv5 {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u16(5)?;
        w.u16(u16::try_from(self.records.0.len()).map_err(|_| invalid(NAME, "too many flows"))?)?;
        w.u32(self.uptime)?;
        w.u32(self.unix_seconds)?;
        w.u32(self.unix_nanoseconds)?;
        w.u32(self.sequence)?;
        w.u8(self.engine_type)?;
        w.u8(self.engine_id)?;
        w.u16(self.sampling)?;
        for r in &self.records.0 {
            match r.get("source") {
                Some(field::Value::Ipv4(v)) => w.put(&v.octets())?,
                _ => return Err(invalid(NAME, "missing IPv4 source")),
            };
            match r.get("destination") {
                Some(field::Value::Ipv4(v)) => w.put(&v.octets())?,
                _ => return Err(invalid(NAME, "missing IPv4 destination")),
            };
            match r.get("next_hop") {
                Some(field::Value::Ipv4(v)) => w.put(&v.octets())?,
                _ => return Err(invalid(NAME, "missing IPv4 next_hop")),
            };
            w.u16(
                u16::try_from(number(r, "input", NAME)?)
                    .map_err(|_| invalid(NAME, "input overflow"))?,
            )?;
            w.u16(
                u16::try_from(number(r, "output", NAME)?)
                    .map_err(|_| invalid(NAME, "output overflow"))?,
            )?;
            w.u32(
                u32::try_from(number(r, "packets", NAME)?)
                    .map_err(|_| invalid(NAME, "packets overflow"))?,
            )?;
            w.u32(
                u32::try_from(number(r, "octets", NAME)?)
                    .map_err(|_| invalid(NAME, "octets overflow"))?,
            )?;
            w.u32(
                u32::try_from(number(r, "first", NAME)?)
                    .map_err(|_| invalid(NAME, "first overflow"))?,
            )?;
            w.u32(
                u32::try_from(number(r, "last", NAME)?)
                    .map_err(|_| invalid(NAME, "last overflow"))?,
            )?;
            w.u16(
                u16::try_from(number(r, "source_port", NAME)?)
                    .map_err(|_| invalid(NAME, "source_port overflow"))?,
            )?;
            w.u16(
                u16::try_from(number(r, "destination_port", NAME)?)
                    .map_err(|_| invalid(NAME, "destination_port overflow"))?,
            )?;
            w.u8(u8::try_from(number(r, "pad1", NAME)?)
                .map_err(|_| invalid(NAME, "pad1 overflow"))?)?;
            w.u8(u8::try_from(number(r, "tcp_flags", NAME)?)
                .map_err(|_| invalid(NAME, "tcp_flags overflow"))?)?;
            w.u8(u8::try_from(number(r, "protocol", NAME)?)
                .map_err(|_| invalid(NAME, "protocol overflow"))?)?;
            w.u8(u8::try_from(number(r,"tos",NAME)?).map_err(|_|invalid(NAME,"tos overflow"))?)?;
            w.u16(
                u16::try_from(number(r, "source_as", NAME)?)
                    .map_err(|_| invalid(NAME, "source_as overflow"))?,
            )?;
            w.u16(
                u16::try_from(number(r, "destination_as", NAME)?)
                    .map_err(|_| invalid(NAME, "destination_as overflow"))?,
            )?;
            w.u8(u8::try_from(number(r, "source_mask", NAME)?)
                .map_err(|_| invalid(NAME, "source_mask overflow"))?)?;
            w.u8(u8::try_from(number(r, "destination_mask", NAME)?)
                .map_err(|_| invalid(NAME, "destination_mask overflow"))?)?;
            w.u16(
                u16::try_from(number(r, "pad2", NAME)?)
                    .map_err(|_| invalid(NAME, "pad2 overflow"))?,
            )?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        if r.u16()? != 5 {
            return Err(unsupported(NAME, "only NetFlow v5"));
        }
        let count = r.u16()? as usize;
        if count > MAX_RECORDS || b.len() != 24 + count * 48 {
            return Err(invalid(NAME, "invalid flow count or length"));
        }
        let mut s = Self {
            uptime: r.u32()?,
            unix_seconds: r.u32()?,
            unix_nanoseconds: r.u32()?,
            sequence: r.u32()?,
            engine_type: r.u8()?,
            engine_id: r.u8()?,
            sampling: r.u16()?,
            ..Self::default()
        };
        if s.unix_nanoseconds >= 1_000_000_000 {
            return Err(invalid(NAME, "invalid timestamp fraction"));
        }
        for _ in 0..count {
            let b = r.take(48)?;
            s.records.0.push(record([
                (
                    "source",
                    field::Value::Ipv4(std::net::Ipv4Addr::from(
                        <[u8; 4]>::try_from(&b[0..4]).unwrap(),
                    )),
                ),
                (
                    "destination",
                    field::Value::Ipv4(std::net::Ipv4Addr::from(
                        <[u8; 4]>::try_from(&b[4..8]).unwrap(),
                    )),
                ),
                (
                    "next_hop",
                    field::Value::Ipv4(std::net::Ipv4Addr::from(
                        <[u8; 4]>::try_from(&b[8..12]).unwrap(),
                    )),
                ),
                (
                    "input",
                    u16::from_be_bytes(b[12..14].try_into().unwrap()).into(),
                ),
                (
                    "output",
                    u16::from_be_bytes(b[14..16].try_into().unwrap()).into(),
                ),
                (
                    "packets",
                    u32::from_be_bytes(b[16..20].try_into().unwrap()).into(),
                ),
                (
                    "octets",
                    u32::from_be_bytes(b[20..24].try_into().unwrap()).into(),
                ),
                (
                    "first",
                    u32::from_be_bytes(b[24..28].try_into().unwrap()).into(),
                ),
                (
                    "last",
                    u32::from_be_bytes(b[28..32].try_into().unwrap()).into(),
                ),
                (
                    "source_port",
                    u16::from_be_bytes(b[32..34].try_into().unwrap()).into(),
                ),
                (
                    "destination_port",
                    u16::from_be_bytes(b[34..36].try_into().unwrap()).into(),
                ),
                ("pad1", b[36].into()),
                ("tcp_flags", b[37].into()),
                ("protocol", b[38].into()),
                ("tos", b[39].into()),
                (
                    "source_as",
                    u16::from_be_bytes(b[40..42].try_into().unwrap()).into(),
                ),
                (
                    "destination_as",
                    u16::from_be_bytes(b[42..44].try_into().unwrap()).into(),
                ),
                ("source_mask", b[44].into()),
                ("destination_mask", b[45].into()),
                (
                    "pad2",
                    u16::from_be_bytes(b[46..48].try_into().unwrap()).into(),
                ),
            ]));
        }
        Ok(s)
    }
}
