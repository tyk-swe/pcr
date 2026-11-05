// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SIP/2.0 requests/responses with byte-preserving ordered headers and Content-Length bodies.

use crate::codec::{DecodeContext, EncodeContext, Error};

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
        let (start_line, headers, body, fields) =
            super::text_message::parse_versioned(NAME, "SIP/2.0", &b)?;
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
