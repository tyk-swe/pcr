// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SIP/2.0 requests/responses with byte-preserving ordered headers and Content-Length bodies.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{Records, message_codec, record};
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
 fn sip_schema() => { protocol: crate::protocol::BuiltinProtocol::Sip.id(), name: "Sip" }
 impl Sip {
    "start_line" => { kind: Bytes, derived: false, required: false, description: "start line", reflect: start_line },
    "headers" => { kind: List, derived: false, required: false, description: "Ordered header fields retaining spaces and case", children: HEADERS, reflect: headers },
    "body" => { kind: Bytes, derived: false, required: false, description: "body", reflect: body },
 }
}
message_codec!(SipCodec, Sip, sip_schema);

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
        Ok(b)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
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
        let body_start = b.len() - body.len();
        let fields = vec![
            crate::layout::FieldLayout {
                index: 0,
                range: crate::layout::ByteRange::new(0, start_line.len()),
            },
            crate::layout::FieldLayout {
                index: 1,
                range: crate::layout::ByteRange::new(start_line.len() + 2, body_start - 2),
            },
            crate::layout::FieldLayout {
                index: 2,
                range: crate::layout::ByteRange::new(body_start, b.len()),
            },
        ];
        Ok((
            Self {
                start_line,
                headers,
                body,
            },
            fields,
        ))
    }
}
