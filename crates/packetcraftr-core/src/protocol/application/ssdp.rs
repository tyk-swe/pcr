// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SSDP discovery messages (UPnP Device Architecture): M-SEARCH, NOTIFY and HTTP/1.1 responses.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{Records, message_codec};
use bytes::Bytes;

use super::text_message::HEADERS;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ssdp {
    pub start_line: Bytes,
    pub headers: Records,
}
impl Default for Ssdp {
    fn default() -> Self {
        Self {
            start_line: Bytes::from_static(b"M-SEARCH * HTTP/1.1"),
            headers: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn ssdp_schema() => { protocol: crate::protocol::BuiltinProtocol::Ssdp.id(), name: "Ssdp" }
 impl Ssdp {
    "start_line" => { kind: Bytes, derived: false, required: false, description: "Verbatim request or response start line", reflect: start_line },
    "headers" => { kind: List, derived: false, required: false, description: "Ordered header names and values", children: HEADERS, reflect: headers },
 }
}
message_codec!(SsdpCodec, Ssdp, ssdp_schema);

const NAME: &str = "ssdp";
impl Ssdp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let w = super::text_message::encode(
            NAME,
            &self.start_line,
            &self.headers,
            &[],
            c.remaining_packet_bytes,
        )?;
        Ok(w)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let (start_line, headers, body) = super::text_message::parse(NAME, &b)?;
        if !body.is_empty() {
            return Err(invalid(NAME, "SSDP datagram has a body"));
        }
        if !(start_line.starts_with(b"M-SEARCH ")
            || start_line.starts_with(b"NOTIFY ")
            || start_line.starts_with(b"HTTP/1.1 "))
        {
            return Err(unsupported(NAME, "unknown SSDP start line"));
        }
        let fields = vec![
            crate::layout::FieldLayout {
                index: 0,
                range: crate::layout::ByteRange::new(0, start_line.len()),
            },
            crate::layout::FieldLayout {
                index: 1,
                range: crate::layout::ByteRange::new(start_line.len() + 2, b.len() - 2),
            },
        ];
        Ok((
            Self {
                start_line,
                headers,
            },
            fields,
        ))
    }
}
