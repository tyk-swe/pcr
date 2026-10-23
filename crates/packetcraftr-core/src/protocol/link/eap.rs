// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! EAP envelope and identity/notification/Nak data (RFC 3748). Other authentication methods remain byte strings.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eap {
    pub code: u8,
    pub identifier: u8,
    pub method: u8,
    pub data: Bytes,
}
impl Default for Eap {
    fn default() -> Self {
        Self {
            code: 1,
            identifier: 0,
            method: 1,
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn eap_schema() => { protocol: crate::layer::Id::new("eap"), name: "Eap" }
 impl Eap {
    "code" => { kind: Unsigned, derived: false, required: false, description: "code", reflect: code },
    "identifier" => { kind: Unsigned, derived: false, required: false, description: "identifier", reflect: identifier },
    "method" => { kind: Unsigned, derived: false, required: false, description: "method", reflect: method },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
 layout fn eap_layout();
}
fn eap_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = eap_layout();
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
message_codec!(EapCodec, Eap, eap_schema, eap_layout_wire);

const NAME: &str = "eap";
impl Eap {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if !(1..=4).contains(&self.code) {
            return Err(unsupported(NAME, "unsupported EAP code"));
        }
        if self.code >= 3 && !self.data.is_empty() {
            return Err(invalid(NAME, "success/failure cannot contain data"));
        }
        let size = 4 + if self.code <= 2 {
            1 + self.data.len()
        } else {
            0
        };
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(self.code)?;
        w.u8(self.identifier)?;
        w.u16(u16::try_from(size).map_err(|_| invalid(NAME, "message too long"))?)?;
        if self.code <= 2 {
            w.u8(self.method)?;
            w.put(&self.data)?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let code = r.u8()?;
        let identifier = r.u8()?;
        let len = r.u16()? as usize;
        if len != b.len() {
            return Err(invalid(NAME, "EAP length mismatch"));
        }
        if !(1..=4).contains(&code) {
            return Err(unsupported(NAME, "unsupported EAP code"));
        }
        let method = if code <= 2 { r.u8()? } else { 0 };
        let data = Bytes::copy_from_slice(r.rest());
        if code >= 3 && !data.is_empty() {
            return Err(invalid(NAME, "success/failure cannot contain data"));
        }
        Ok(Self {
            code,
            identifier,
            method,
            data,
        })
    }
}
