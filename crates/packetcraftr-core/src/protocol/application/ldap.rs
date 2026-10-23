// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! LDAPv3 Bind/Search/Unbind BER envelopes (RFC 4511). Operation fields retain their ASN.1 tag and original content.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use super::ber;
use crate::protocol::common::structured::member;
const FIELDS: &[crate::layer::FieldSchema] = &[
    member("tag", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ldap {
    pub message_id: u32,
    pub operation: u8,
    pub fields: Records,
    pub controls: Bytes,
}
impl Default for Ldap {
    fn default() -> Self {
        Self {
            message_id: 1,
            operation: 0x42,
            fields: Records::default(),
            controls: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn ldap_schema() => { protocol: crate::layer::Id::new("ldap"), name: "Ldap" }
 impl Ldap {
    "message_id" => { kind: Unsigned, derived: false, required: false, description: "message id", reflect: message_id },
    "operation" => { kind: Unsigned, derived: false, required: false, description: "operation", reflect: operation },
    "fields" => { kind: List, derived: false, required: false, description: "Ordered operation BER fields", children: FIELDS, reflect: fields },
    "controls" => { kind: Bytes, derived: false, required: false, description: "controls", reflect: controls },
 }
 layout fn ldap_layout();
}
fn ldap_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = ldap_layout();
    let fields = Vec::new();
    let _ = b;
    fields
}
message_codec!(LdapCodec, Ldap, ldap_schema, ldap_layout_wire);

const NAME: &str = "ldap";
impl Ldap {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let max = c.remaining_packet_bytes;
        if self.message_id > 0x7fffffff {
            return Err(invalid(NAME, "message ID overflow"));
        }
        let mut w = Writer::new(NAME, max);
        ber::int(&mut w, 2, self.message_id.into())?;
        let mut p = Writer::new(NAME, max);
        for r in &self.fields.0 {
            ber::put(
                &mut p,
                u8::try_from(number(r, "tag", NAME)?).map_err(|_| invalid(NAME, "tag overflow"))?,
                data(r, "value", NAME)?,
            )?;
        }
        if self.operation == 0x42 && !p.bytes.is_empty() {
            return Err(invalid(NAME, "Unbind must be empty"));
        }
        ber::put(&mut w, self.operation, &p.bytes)?;
        w.put(&self.controls)?;
        let mut top = Writer::new(NAME, max);
        ber::put(&mut top, 0x30, &w.bytes)?;
        Ok(top.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        ber::validate(NAME, &b)?;
        let mut top = Reader::new(NAME, &b);
        let mut r = Reader::new(NAME, ber::expect(&mut top, 0x30)?);
        top.finish()?;
        let id = ber::integer(ber::expect(&mut r, 2)?, NAME)?;
        if !(0..=0x7fffffff).contains(&id) {
            return Err(invalid(NAME, "invalid message ID"));
        }
        let (operation, payload) = ber::take(&mut r)?;
        if !matches!(operation, 0x60 | 0x61 | 0x42 | 0x63 | 0x64 | 0x65 | 0x73) {
            return Err(unsupported(
                NAME,
                "operation outside Bind/Search/Unbind subset",
            ));
        }
        if operation == 0x42 && !payload.is_empty() {
            return Err(invalid(NAME, "Unbind must be empty"));
        }
        let mut fields = Records::default();
        let mut p = Reader::new(NAME, payload);
        while p.left() > 0 {
            let (tag, value) = ber::take(&mut p)?;
            fields.0.push(record([
                ("tag", tag.into()),
                ("value", Bytes::copy_from_slice(value).into()),
            ]));
        }
        let controls = Bytes::copy_from_slice(r.rest());
        if !controls.is_empty() {
            let mut r = Reader::new(NAME, &controls);
            ber::expect(&mut r, 0xa0)?;
            r.finish()?;
        }
        if operation == 0x60 {
            let mut p = Reader::new(NAME, payload);
            if ber::integer(ber::expect(&mut p, 2)?, NAME)? != 3 {
                return Err(unsupported(NAME, "only LDAPv3"));
            }
            ber::expect(&mut p, 4)?;
            let (tag, _) = ber::take(&mut p)?;
            if !matches!(tag, 0x80 | 0xa3) {
                return Err(invalid(NAME, "invalid authentication choice"));
            }
            p.finish()?;
        }
        if operation == 0x63 {
            let mut p = Reader::new(NAME, payload);
            for tag in [4, 10, 10, 2, 2, 1] {
                ber::expect(&mut p, tag)?;
            }
            ber::take(&mut p)?;
            ber::expect(&mut p, 0x30)?;
            p.finish()?;
        }
        Ok(Self {
            message_id: id as u32,
            operation,
            fields,
            controls,
        })
    }
}
