// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PPP control protocol header and ordered options; unrecognized option values remain opaque.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const OPTIONS: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PppLcp {
    pub code: u8,
    pub identifier: u8,
    pub options: Records,
    pub data: Bytes,
}
impl Default for PppLcp {
    fn default() -> Self {
        Self {
            code: 1,
            identifier: 0,
            options: Records::default(),
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn ppplcp_schema() => { protocol: crate::layer::Id::new("ppp_lcp"), name: "PppLcp" }
 impl PppLcp {
    "code" => { kind: Unsigned, derived: false, required: false, description: "code", reflect: code },
    "identifier" => { kind: Unsigned, derived: false, required: false, description: "identifier", reflect: identifier },
    "options" => { kind: List, derived: false, required: false, description: "Ordered control protocol options", children: OPTIONS, reflect: options },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
 layout fn ppplcp_layout();
}
fn ppplcp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = ppplcp_layout();
    let mut fields = Vec::new();
    if !b.is_empty() {
        fields.push(crate::layout::FieldLayout {
            name: "code",
            range: crate::layout::ByteRange::new(0, 1),
        });
    }
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "identifier",
            range: crate::layout::ByteRange::new(1, 2),
        });
    }
    fields
}
message_codec!(PppLcpCodec, PppLcp, ppplcp_schema, ppplcp_layout_wire);

const NAME: &str = "ppp_lcp";
impl PppLcp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.code == 0 {
            return Err(invalid(NAME, "zero code"));
        }
        let mut p = Writer::new(NAME, c.remaining_packet_bytes);
        if matches!(self.code, 1..=4) {
            if !self.data.is_empty() {
                return Err(invalid(NAME, "configuration uses options, not data"));
            }
            for item in &self.options.0 {
                let kind = u8::try_from(number(item, "kind", NAME)?)
                    .map_err(|_| invalid(NAME, "option kind overflow"))?;
                let b = data(item, "value", NAME)?;
                p.u8(kind)?;
                p.u8(u8::try_from(b.len() + 2)
                    .map_err(|_| invalid(NAME, "option length overflow"))?)?;
                p.put(b)?;
            }
        } else {
            if !self.options.0.is_empty() {
                return Err(invalid(NAME, "nonconfiguration message uses data"));
            }
            p.put(&self.data)?;
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(self.code)?;
        w.u8(self.identifier)?;
        w.u16(
            u16::try_from(p.bytes.len() + 4)
                .map_err(|_| invalid(NAME, "message length overflow"))?,
        )?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let mut s = Self {
            code: r.u8()?,
            identifier: r.u8()?,
            ..Self::default()
        };
        let len = r.u16()? as usize;
        if len != b.len() || s.code == 0 {
            return Err(invalid(NAME, "invalid control header"));
        }
        if matches!(s.code, 1..=4) {
            while r.left() > 0 {
                if s.options.0.len() == MAX_RECORDS {
                    return Err(invalid(NAME, "too many options"));
                }
                let kind = r.u8()?;
                let len = r.u8()?;
                if len < 2 {
                    return Err(invalid(NAME, "option shorter than header"));
                }
                s.options.0.push(record([
                    ("kind", kind.into()),
                    (
                        "value",
                        Bytes::copy_from_slice(r.take(len as usize - 2)?).into(),
                    ),
                ]));
            }
        } else {
            s.data = Bytes::copy_from_slice(r.rest());
        }
        Ok(s)
    }
}
