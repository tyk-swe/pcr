// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SIP/2.0 requests/responses with byte-preserving ordered headers and Content-Length bodies.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use super::text_message::HEADERS;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sip {
    pub start_line: Bytes,
    pub headers: Records,
    pub body: Bytes,
}
impl Default for Sip {
    fn default() -> Self {
        Self {
            start_line: Bytes::from_static(b"OPTIONS sip:service SIP/2.0"),
            headers: Records(vec![record([
                ("name", Bytes::from_static(b"Content-Length").into()),
                ("value", Bytes::from_static(b" 0").into()),
            ])]),
            body: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn sip_schema() => { protocol: crate::layer::Id::new("sip"), name: "Sip" }
 impl Sip {
    "start_line" => { kind: Bytes, derived: false, required: false, description: "start line", reflect: start_line },
    "headers" => { kind: List, derived: false, required: false, description: "Ordered header fields retaining spaces and case", children: HEADERS, reflect: headers },
    "body" => { kind: Bytes, derived: false, required: false, description: "body", reflect: body },
 }
}
fn sip_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if let Some(first) = b.windows(2).position(|p| p == b"\r\n") {
        fields.push(crate::layout::FieldLayout {
            name: "start_line",
            range: crate::layout::ByteRange::new(0, first),
        });
        if let Some(end) = b.windows(4).position(|p| p == b"\r\n\r\n") {
            fields.push(crate::layout::FieldLayout {
                name: "headers",
                range: crate::layout::ByteRange::new(first + 2, end + 2),
            });
            fields.push(crate::layout::FieldLayout {
                name: "body",
                range: crate::layout::ByteRange::new(end + 4, b.len()),
            });
        }
    }
    fields
}
message_codec!(SipCodec, Sip, sip_schema, sip_layout_wire);

const NAME: &str = "sip";
impl Sip {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let b = super::text_message::encode(
            NAME,
            &self.start_line,
            &self.headers,
            &self.body,
            c.remaining_packet_bytes,
        )?;
        Self::parse_wire(
            Bytes::copy_from_slice(&b),
            &DecodeContext {
                parent: None,
                registry: c.registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )?;
        Ok(b)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let (start_line, headers, body) = super::text_message::parse(NAME, &b)?;
        let text =
            std::str::from_utf8(&start_line).map_err(|_| invalid(NAME, "invalid start line"))?;
        let parts: Vec<_> = text.splitn(3, ' ').collect();
        if parts.len() != 3
            || !(parts[0] == "SIP/2.0"
                && parts[1].len() == 3
                && parts[1].bytes().all(|b| b.is_ascii_digit())
                || parts[2] == "SIP/2.0"
                    && !parts[1].is_empty()
                    && super::text_message::is_token(NAME, parts[0].as_bytes()))
        {
            return Err(unsupported(NAME, "unsupported start line or version"));
        }
        Ok(Self {
            start_line,
            headers,
            body,
        })
    }
}
