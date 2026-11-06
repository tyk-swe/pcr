// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RADIUS envelopes and attributes (RFC 2865). Authenticators and encrypted attributes are supplied bytes.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::field;
use crate::protocol::common::invalid;
use crate::protocol::message::{
    MAX_RECORDS, Reader, Records, Writer, data, message_codec, number, record,
};
use bytes::Bytes;

use crate::protocol::common::structured::member;
const ATTRIBUTES: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Radius {
    pub code: u8,
    pub identifier: u8,
    pub authenticator: Bytes,
    pub attributes: Records,
}
impl Default for Radius {
    fn default() -> Self {
        Self {
            code: 1,
            identifier: 0,
            authenticator: Bytes::from_static(&[0; 16]),
            attributes: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn radius_schema() => { protocol: crate::protocol::BuiltinProtocol::Radius.id(), name: "Radius" }
 impl Radius {
    "code" => { kind: Unsigned, derived: false, required: false, description: "code", reflect: code },
    "identifier" => { kind: Unsigned, derived: false, required: false, description: "identifier", reflect: identifier },
    "authenticator" => { kind: Bytes, derived: false, required: false, description: "authenticator", reflect: authenticator },
    "attributes" => { kind: List, derived: false, required: false, description: "Ordered attributes including unknown and duplicate types", children: ATTRIBUTES, reflect: attributes },
 }
}
message_codec!(RadiusCodec, Radius, radius_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::Radius.as_str();
impl Radius {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.code == 0 || self.authenticator.len() != 16 {
            return Err(invalid(NAME, "invalid code or authenticator width"));
        }
        let mut body = Writer::new(NAME, 4076);
        for r in &self.attributes.0 {
            let b = data(r, "value", NAME)?;
            body.u8(u8::try_from(number(r, "kind", NAME)?)
                .map_err(|_| invalid(NAME, "attribute type overflow"))?)?;
            body.u8(u8::try_from(b.len() + 2).map_err(|_| invalid(NAME, "attribute too long"))?)?;
            body.put(b)?;
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(self.code)?;
        w.u8(self.identifier)?;
        w.u16((body.bytes.len() + 20) as u16)?;
        w.put(&self.authenticator)?;
        w.put(&body.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let mut r = Reader::new(NAME, &b);
        r.mark(0, 0..1);
        r.mark(1, 1..2);
        r.mark(2, 4..20);
        r.mark(3, 20..b.len());
        let code = r.u8()?;
        let identifier = r.u8()?;
        let len = r.u16()? as usize;
        if code == 0 || len != b.len() || !(20..=4096).contains(&len) {
            return Err(invalid(NAME, "invalid header"));
        }
        let authenticator = Bytes::copy_from_slice(r.take(16)?);
        let mut attributes = Records::default();
        while r.left() > 0 {
            if attributes.0.len() == MAX_RECORDS {
                return Err(invalid(NAME, "too many attributes"));
            }
            let kind = r.u8()?;
            let n = r.u8()?;
            if n < 2 {
                return Err(invalid(NAME, "short attribute"));
            }
            attributes.0.push(record([
                ("kind", kind.into()),
                (
                    "value",
                    Bytes::copy_from_slice(r.take(n as usize - 2)?).into(),
                ),
            ]));
        }
        Ok((
            Self {
                code,
                identifier,
                authenticator,
                attributes,
            },
            r.take_layouts(),
        ))
    }
}
