// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! STUN Binding messages (RFC 8489), including unknown attributes and alignment bytes. Integrity is not authenticated.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const ATTRIBUTES: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
    member("padding", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stun {
    pub message_type: u16,
    pub transaction_id: Bytes,
    pub attributes: Records,
}
impl Default for Stun {
    fn default() -> Self {
        Self {
            message_type: 1,
            transaction_id: Bytes::from_static(&[0; 12]),
            attributes: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn stun_schema() => { protocol: crate::layer::Id::new("stun"), name: "Stun" }
 impl Stun {
    "message_type" => { kind: Unsigned, derived: false, required: false, description: "message type", reflect: message_type },
    "transaction_id" => { kind: Bytes, derived: false, required: false, description: "transaction id", reflect: transaction_id },
    "attributes" => { kind: List, derived: false, required: false, description: "Ordered attributes and alignment padding", children: ATTRIBUTES, reflect: attributes },
 }
}
fn stun_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "message_type",
            range: crate::layout::ByteRange::new(0, 2),
        });
    }
    if 20 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "transaction_id",
            range: crate::layout::ByteRange::new(8, 20),
        });
    }
    if b.len() <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "attributes",
            range: crate::layout::ByteRange::new(20, b.len()),
        });
    }
    fields
}
message_codec!(StunCodec, Stun, stun_schema, stun_layout_wire);

const NAME: &str = "stun";
impl Stun {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if !matches!(self.message_type, 1 | 0x11 | 0x101 | 0x111) {
            return Err(unsupported(NAME, "only Binding messages"));
        }
        if self.transaction_id.len() != 12 {
            return Err(invalid(NAME, "transaction ID requires 12 bytes"));
        }
        let mut body = Writer::new(NAME, c.remaining_packet_bytes);
        for a in &self.attributes.0 {
            let v = data(a, "value", NAME)?;
            body.u16(
                u16::try_from(number(a, "kind", NAME)?)
                    .map_err(|_| invalid(NAME, "attribute type overflow"))?,
            )?;
            body.u16(u16::try_from(v.len()).map_err(|_| invalid(NAME, "attribute too long"))?)?;
            body.put(v)?;
            let pad = (4 - v.len() % 4) % 4;
            if let Some(field::Value::Bytes(b)) = a.get("padding") {
                if b.len() != pad {
                    return Err(invalid(NAME, "invalid padding"));
                }
                body.put(b)?;
            } else {
                body.put(&[0; 3][..pad])?;
            }
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u16(self.message_type)?;
        w.u16(u16::try_from(body.bytes.len()).map_err(|_| invalid(NAME, "message too long"))?)?;
        w.u32(0x2112a442)?;
        w.put(&self.transaction_id)?;
        w.put(&body.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let message_type = r.u16()?;
        if !matches!(message_type, 1 | 0x11 | 0x101 | 0x111) {
            return Err(unsupported(NAME, "only Binding messages"));
        }
        let len = r.u16()? as usize;
        if !len.is_multiple_of(4) || len + 20 != b.len() {
            return Err(invalid(NAME, "invalid message length"));
        }
        if r.u32()? != 0x2112a442 {
            return Err(unsupported(NAME, "invalid magic cookie"));
        }
        let transaction_id = Bytes::copy_from_slice(r.take(12)?);
        let mut attributes = Records::default();
        while r.left() > 0 {
            if attributes.0.len() == MAX_RECORDS {
                return Err(invalid(NAME, "too many attributes"));
            }
            let kind = r.u16()?;
            let n = r.u16()? as usize;
            let value = Bytes::copy_from_slice(r.take(n)?);
            let padding = Bytes::copy_from_slice(r.take((4 - n % 4) % 4)?);
            attributes.0.push(record([
                ("kind", kind.into()),
                ("value", value.into()),
                ("padding", padding.into()),
            ]));
        }
        Ok(Self {
            message_type,
            transaction_id,
            attributes,
        })
    }
}
