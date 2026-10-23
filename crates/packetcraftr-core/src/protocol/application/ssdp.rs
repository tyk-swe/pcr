// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SSDP discovery messages (UPnP Device Architecture): M-SEARCH, NOTIFY and HTTP/1.1 responses.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
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
 fn ssdp_schema() => { protocol: crate::layer::Id::new("ssdp"), name: "Ssdp" }
 impl Ssdp {
    "start_line" => { kind: Bytes, derived: false, required: false, description: "Verbatim request or response start line", reflect: start_line },
    "headers" => { kind: List, derived: false, required: false, description: "Ordered header names and values", children: HEADERS, reflect: headers },
 }
 layout fn ssdp_layout();
}
fn ssdp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = ssdp_layout();
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
        }
    }
    fields
}
message_codec!(SsdpCodec, Ssdp, ssdp_schema, ssdp_layout_wire);

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
        Self::parse_wire(
            Bytes::copy_from_slice(&w),
            &DecodeContext {
                parent: None,
                registry: c.registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )?;
        Ok(w)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
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
        Ok(Self {
            start_line,
            headers,
        })
    }
}
