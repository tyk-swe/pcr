// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RIP route messages (RFC 2080).

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const ROUTES: &[crate::layer::FieldSchema] = &[
    member("prefix", field::Kind::Ipv6, &[]),
    member("length", field::Kind::Unsigned, &[]),
    member("tag", field::Kind::Unsigned, &[]),
    member("metric", field::Kind::Unsigned, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ripng {
    pub command: u8,
    pub routes: Records,
}
impl Default for Ripng {
    fn default() -> Self {
        Self {
            command: 1,
            routes: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn ripng_schema() => { protocol: crate::layer::Id::new("ripng"), name: "Ripng" }
 impl Ripng {
    "command" => { kind: Unsigned, derived: false, required: false, description: "command", reflect: command },
    "routes" => { kind: List, derived: false, required: false, description: "Ordered route entries", children: ROUTES, reflect: routes },
 }
 layout fn ripng_layout();
}
fn ripng_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = ripng_layout();
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
message_codec!(RipngCodec, Ripng, ripng_schema, ripng_layout_wire);

const NAME: &str = "ripng";
impl Ripng {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if !matches!(self.command, 1 | 2) {
            return Err(invalid(NAME, "invalid command"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.put(&[self.command, 1, 0, 0])?;
        for r in &self.routes.0 {
            let prefix = match r.get("prefix") {
                Some(field::Value::Ipv6(v)) => v.octets(),
                _ => return Err(invalid(NAME, "route requires IPv6 prefix")),
            };
            w.put(&prefix)?;
            w.u16(
                u16::try_from(number(r, "tag", NAME)?)
                    .map_err(|_| invalid(NAME, "tag overflow"))?,
            )?;
            let len = number(r, "length", NAME)?;
            let metric = number(r, "metric", NAME)?;
            if len > 128 || !((1..=16).contains(&metric) || metric == 255) {
                return Err(invalid(NAME, "invalid prefix or metric"));
            }
            w.u8(len as u8)?;
            w.u8(metric as u8)?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let command = r.u8()?;
        if !matches!(command, 1 | 2) {
            return Err(invalid(NAME, "invalid command"));
        }
        if r.u8()? != 1 {
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
            let prefix = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&p[..16]).unwrap());
            let tag = u16::from_be_bytes([p[16], p[17]]);
            if p[18] > 128 || !((1..=16).contains(&p[19]) || p[19] == 255) {
                return Err(invalid(NAME, "invalid prefix or metric"));
            }
            routes.0.push(record([
                ("prefix", field::Value::Ipv6(prefix)),
                ("tag", tag.into()),
                ("length", p[18].into()),
                ("metric", p[19].into()),
            ]));
        }
        Ok(Self { command, routes })
    }
}
