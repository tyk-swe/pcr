// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RIP route messages (RFC 2453).

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const ROUTES: &[crate::layer::FieldSchema] = &[
    member("family", field::Kind::Unsigned, &[]),
    member("address", field::Kind::Ipv4, &[]),
    member("mask", field::Kind::Ipv4, &[]),
    member("next_hop", field::Kind::Ipv4, &[]),
    member("authentication", field::Kind::Bytes, &[]),
    member("tag", field::Kind::Unsigned, &[]),
    member("metric", field::Kind::Unsigned, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ripv2 {
    pub command: u8,
    pub routes: Records,
}
impl Default for Ripv2 {
    fn default() -> Self {
        Self {
            command: 1,
            routes: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn ripv2_schema() => { protocol: crate::layer::Id::new("ripv2"), name: "Ripv2" }
 impl Ripv2 {
    "command" => { kind: Unsigned, derived: false, required: false, description: "command", reflect: command },
    "routes" => { kind: List, derived: false, required: false, description: "Ordered route entries", children: ROUTES, reflect: routes },
 }
}
fn ripv2_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if !b.is_empty() {
        fields.push(crate::layout::FieldLayout {
            name: "command",
            range: crate::layout::ByteRange::new(0, 1),
        });
    }
    if b.len() <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "routes",
            range: crate::layout::ByteRange::new(4, b.len()),
        });
    }
    fields
}
message_codec!(Ripv2Codec, Ripv2, ripv2_schema, ripv2_layout_wire);

const NAME: &str = "ripv2";
impl Ripv2 {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if !matches!(self.command, 1 | 2) {
            return Err(invalid(NAME, "invalid command"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.put(&[self.command, 2, 0, 0])?;
        for r in &self.routes.0 {
            if let Some(field::Value::Bytes(auth)) = r.get("authentication") {
                if auth.len() != 20 || auth[..2] != [255, 255] {
                    return Err(invalid(NAME, "invalid authentication entry"));
                }
                w.put(auth)?;
                continue;
            }
            w.u16(
                u16::try_from(number(r, "family", NAME)?)
                    .map_err(|_| invalid(NAME, "family overflow"))?,
            )?;
            w.u16(
                u16::try_from(number(r, "tag", NAME)?)
                    .map_err(|_| invalid(NAME, "tag overflow"))?,
            )?;
            for key in ["address", "mask", "next_hop"] {
                match r.get(key) {
                    Some(field::Value::Ipv4(v)) => w.put(&v.octets())?,
                    _ => return Err(invalid(NAME, "route requires IPv4 addresses")),
                }
            }
            let metric = number(r, "metric", NAME)?;
            if !(1..=16).contains(&metric) {
                return Err(invalid(NAME, "invalid metric"));
            }
            w.u32(metric as u32)?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let command = r.u8()?;
        if !matches!(command, 1 | 2) {
            return Err(invalid(NAME, "invalid command"));
        }
        if r.u8()? != 2 {
            return Err(unsupported(NAME, "unsupported version"));
        }
        if r.u16()? != 0 {
            return Err(invalid(NAME, "reserved header is nonzero"));
        }
        let mut routes = Records::default();
        while r.left() > 0 {
            if routes.0.len() == MAX_RECORDS {
                return Err(invalid(NAME, "too many routes"));
            }
            let p = r.take(20)?;
            let family = u16::from_be_bytes([p[0], p[1]]);
            if family == 65535 {
                routes.0.push(record([(
                    "authentication",
                    Bytes::copy_from_slice(p).into(),
                )]));
                continue;
            }
            let tag = u16::from_be_bytes([p[2], p[3]]);
            let ip =
                |i| field::Value::Ipv4(std::net::Ipv4Addr::new(p[i], p[i + 1], p[i + 2], p[i + 3]));
            let metric = u32::from_be_bytes(p[16..20].try_into().unwrap());
            if !(1..=16).contains(&metric) {
                return Err(invalid(NAME, "invalid metric"));
            }
            routes.0.push(record([
                ("family", family.into()),
                ("tag", tag.into()),
                ("address", ip(4)),
                ("mask", ip(8)),
                ("next_hop", ip(12)),
                ("metric", metric.into()),
            ]));
        }
        Ok(Self { command, routes })
    }
}
