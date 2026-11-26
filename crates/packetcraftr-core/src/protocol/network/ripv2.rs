// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RIP route messages (RFC 2453).

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::field;
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{
    MAX_RECORDS, Reader, Records, Writer, message_codec, number, record,
};
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
crate::layer::reflective_layer! {
 fn ripv2_schema() => { protocol: crate::protocol::BuiltinProtocol::Ripv2.id(), name: "Ripv2" }
 impl Ripv2 {
    "command" => { kind: Unsigned, derived: false, required: false, description: "command", reflect: command },
    "routes" => { kind: List, derived: false, required: false, description: "Ordered route entries", children: ROUTES, reflect: routes },
 }
}
message_codec!(Ripv2Codec, Ripv2, ripv2_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::Ripv2.as_str();

pub(super) fn begin_rip_encode(
    name: &'static str,
    command: u8,
    version: u8,
    c: &EncodeContext<'_>,
) -> Result<Writer, Error> {
    if !matches!(command, 1 | 2) {
        return Err(invalid(name, "invalid command"));
    }
    let mut w = Writer::new(name, c.remaining_packet_bytes);
    w.put(&[command, version, 0, 0])?;
    Ok(w)
}

pub(super) fn parse_rip_wire(
    name: &'static str,
    version: u8,
    b: &Bytes,
    mut parse_entry: impl FnMut(
        &[u8],
    ) -> Result<std::collections::BTreeMap<String, field::Value>, Error>,
) -> Result<(u8, Records, Vec<crate::layout::FieldLayout>), Error> {
    let mut r = Reader::new(name, b);
    r.mark(0, 0..1);
    r.mark(1, 4..b.len());
    let command = r.u8()?;
    if !matches!(command, 1 | 2) {
        return Err(invalid(name, "invalid command"));
    }
    if r.u8()? != version {
        return Err(unsupported(name, "unsupported version"));
    }
    if r.u16()? != 0 {
        return Err(invalid(name, "reserved header is nonzero"));
    }
    let mut routes = Records::default();
    while r.left() > 0 {
        if routes.0.len() == MAX_RECORDS {
            return Err(invalid(name, "too many routes"));
        }
        routes.0.push(parse_entry(r.take(20)?)?);
    }
    Ok((command, routes, r.take_layouts()))
}

impl Ripv2 {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut w = begin_rip_encode(NAME, self.command, 2, c)?;
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
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let (command, routes, layouts) = parse_rip_wire(NAME, 2, &b, |p| {
            let family = u16::from_be_bytes([p[0], p[1]]);
            if family == 65535 {
                return Ok(record([(
                    "authentication",
                    Bytes::copy_from_slice(p).into(),
                )]));
            }
            let tag = u16::from_be_bytes([p[2], p[3]]);
            let ip =
                |i| field::Value::Ipv4(std::net::Ipv4Addr::new(p[i], p[i + 1], p[i + 2], p[i + 3]));
            let metric = u32::from_be_bytes(p[16..20].try_into().unwrap());
            if !(1..=16).contains(&metric) {
                return Err(invalid(NAME, "invalid metric"));
            }
            Ok(record([
                ("family", family.into()),
                ("tag", tag.into()),
                ("address", ip(4)),
                ("mask", ip(8)),
                ("next_hop", ip(12)),
                ("metric", metric.into()),
            ]))
        })?;
        Ok((Self { command, routes }, layouts))
    }
}
