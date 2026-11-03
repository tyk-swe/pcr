// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! CoAP version 1 (RFC 7252). Options remain ordered, including repeated options.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::field;
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{
    MAX_RECORDS, Reader, Records, Writer, data, message_codec, number, record,
};
use bytes::Bytes;

use crate::protocol::common::structured::member;
const OPTIONS: &[crate::layer::FieldSchema] = &[
    member("number", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coap {
    pub version: u8,
    pub message_type: u8,
    pub code: u8,
    pub message_id: u16,
    pub token: Bytes,
    pub options: Records,
    pub payload: Bytes,
}
impl Default for Coap {
    fn default() -> Self {
        Self {
            version: 1,
            message_type: 0,
            code: 1,
            message_id: 1,
            token: Bytes::new(),
            options: Records::default(),
            payload: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn coap_schema() => { protocol: crate::protocol::BuiltinProtocol::Coap.id(), name: "Coap" }
 impl Coap {
    "version" => { kind: Unsigned, derived: false, required: false, description: "version", reflect: version },
    "message_type" => { kind: Unsigned, derived: false, required: false, description: "message type", reflect: message_type },
    "code" => { kind: Unsigned, derived: false, required: false, description: "code", reflect: code },
    "message_id" => { kind: Unsigned, derived: false, required: false, description: "message id", reflect: message_id },
    "token" => { kind: Bytes, derived: false, required: false, description: "token", reflect: token },
    "options" => { kind: List, derived: false, required: false, description: "Ordered option numbers and raw values", children: OPTIONS, reflect: options },
    "payload" => { kind: Bytes, derived: false, required: false, description: "payload", reflect: payload },
 }
}
message_codec!(CoapCodec, Coap, coap_schema);

const NAME: &str = "coap";
impl Coap {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.version != 1 || self.message_type > 3 || self.token.len() > 8 {
            return Err(invalid(NAME, "invalid CoAP header"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(self.version << 6 | self.message_type << 4 | self.token.len() as u8)?;
        w.u8(self.code)?;
        w.u16(self.message_id)?;
        w.put(&self.token)?;
        let mut previous = 0;
        for option in &self.options.0 {
            let n = number(option, "number", NAME)?;
            let b = data(option, "value", NAME)?;
            if n < previous {
                return Err(invalid(NAME, "options must be sorted by number"));
            }
            let (dn, de) = option_number(n - previous)?;
            let (ln, le) = option_number(b.len() as u64)?;
            w.u8(dn << 4 | ln)?;
            w.put(&de)?;
            w.put(&le)?;
            w.put(b)?;
            previous = n;
        }
        if !self.payload.is_empty() {
            w.u8(255)?;
            w.put(&self.payload)?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let mut r = Reader::new(NAME, &b);
        r.mark(0, 0..1);
        r.mark(1, 0..1);
        r.mark(2, 1..2);
        r.mark(3, 2..4);
        let h = r.u8()?;
        if h >> 6 != 1 {
            return Err(unsupported(NAME, "only CoAP version 1 is supported"));
        }
        let tkl = h & 15;
        if tkl > 8 {
            return Err(invalid(NAME, "token exceeds eight bytes"));
        }
        let mut s = Self {
            version: 1,
            message_type: h >> 4 & 3,
            code: r.u8()?,
            message_id: r.u16()?,
            ..Self::default()
        };
        s.token = Bytes::copy_from_slice(r.take(tkl as usize)?);
        let options_start = r.pos;
        let mut payload_start = None;
        let mut n = 0u64;
        while r.left() > 0 {
            let option_start = r.pos;
            let h = r.u8()?;
            if h == 255 {
                if r.left() == 0 {
                    return Err(invalid(NAME, "empty payload marker"));
                }
                r.mark(4, 4..options_start);
                r.mark(5, options_start..option_start);
                r.mark(6, r.pos..b.len());
                payload_start = Some(r.pos);
                s.payload = Bytes::copy_from_slice(r.rest());
                break;
            }
            n = n
                .checked_add(read_option(h >> 4, &mut r)?)
                .ok_or_else(|| invalid(NAME, "option number overflow"))?;
            let len = read_option(h & 15, &mut r)? as usize;
            if s.options.0.len() == MAX_RECORDS {
                return Err(invalid(NAME, "too many options"));
            }
            s.options.0.push(record([
                ("number", n.into()),
                ("value", Bytes::copy_from_slice(r.take(len)?).into()),
            ]));
        }
        if s.code == 0 && (!s.token.is_empty() || !s.options.0.is_empty() || !s.payload.is_empty())
        {
            return Err(invalid(NAME, "empty CoAP message contains data"));
        }
        if payload_start.is_none() {
            r.mark(4, 4..options_start);
            r.mark(5, options_start..r.pos);
            r.mark(6, r.pos..b.len());
        }
        Ok((s, r.take_layouts()))
    }
}
fn option_number(n: u64) -> Result<(u8, Vec<u8>), Error> {
    Ok(match n {
        0..=12 => (n as u8, vec![]),
        13..=268 => (13, vec![(n - 13) as u8]),
        269..=65804 => (14, ((n - 269) as u16).to_be_bytes().to_vec()),
        _ => return Err(invalid(NAME, "option delta or size too large")),
    })
}
fn read_option(n: u8, r: &mut Reader<'_>) -> Result<u64, Error> {
    match n {
        0..=12 => Ok(n.into()),
        13 => Ok(13 + u64::from(r.u8()?)),
        14 => Ok(269 + u64::from(r.u16()?)),
        _ => Err(invalid(NAME, "reserved option nibble")),
    }
}
