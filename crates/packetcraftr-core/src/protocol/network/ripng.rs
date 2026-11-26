// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RIP route messages (RFC 2080).

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::field;
use crate::protocol::common::invalid;
use crate::protocol::message::{Records, message_codec, number, record};
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
crate::layer::reflective_layer! {
 fn ripng_schema() => { protocol: crate::protocol::BuiltinProtocol::Ripng.id(), name: "Ripng" }
 impl Ripng {
    "command" => { kind: Unsigned, derived: false, required: false, description: "command", reflect: command },
    "routes" => { kind: List, derived: false, required: false, description: "Ordered route entries", children: ROUTES, reflect: routes },
 }
}
message_codec!(RipngCodec, Ripng, ripng_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::Ripng.as_str();
impl Ripng {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut w = super::ripv2::begin_rip_encode(NAME, self.command, 1, c)?;
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
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let (command, routes, layouts) = super::ripv2::parse_rip_wire(NAME, 1, &b, |p| {
            let prefix = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&p[..16]).unwrap());
            let tag = u16::from_be_bytes([p[16], p[17]]);
            if p[18] > 128 || !((1..=16).contains(&p[19]) || p[19] == 255) {
                return Err(invalid(NAME, "invalid prefix or metric"));
            }
            Ok(record([
                ("prefix", field::Value::Ipv6(prefix)),
                ("tag", tag.into()),
                ("length", p[18].into()),
                ("metric", p[19].into()),
            ]))
        })?;
        Ok((Self { command, routes }, layouts))
    }
}
