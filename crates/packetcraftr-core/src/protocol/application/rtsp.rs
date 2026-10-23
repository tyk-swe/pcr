// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RTSP/1.0 requests/responses with byte-preserving ordered headers and Content-Length bodies.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use super::text_message::HEADERS;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rtsp {
    pub start_line: Bytes,
    pub headers: Records,
    pub body: Bytes,
    pub interleaved: bool,
    pub channel: u8,
}
impl Default for Rtsp {
    fn default() -> Self {
        Self {
            start_line: Bytes::from_static(b"OPTIONS * RTSP/1.0"),
            headers: Records(vec![record([
                ("name", Bytes::from_static(b"Content-Length").into()),
                ("value", Bytes::from_static(b" 0").into()),
            ])]),
            body: Bytes::new(),
            interleaved: false,
            channel: 0,
        }
    }
}
crate::reflective_layer! {
 fn rtsp_schema() => { protocol: crate::layer::Id::new("rtsp"), name: "Rtsp" }
 impl Rtsp {
    "start_line" => { kind: Bytes, derived: false, required: false, description: "start line", reflect: start_line },
    "headers" => { kind: List, derived: false, required: false, description: "Ordered header fields retaining spaces and case", children: HEADERS, reflect: headers },
    "body" => { kind: Bytes, derived: false, required: false, description: "body", reflect: body },
    "interleaved" => { kind: Bool, derived: false, required: false, description: "interleaved", reflect: interleaved },
    "channel" => { kind: Unsigned, derived: false, required: false, description: "channel", reflect: channel },
 }
 layout fn rtsp_layout();
}
fn rtsp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = rtsp_layout();
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
message_codec!(RtspCodec, Rtsp, rtsp_schema, rtsp_layout_wire);

const NAME: &str = "rtsp";
impl Rtsp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.interleaved {
            let mut w = Writer::new(NAME, c.remaining_packet_bytes);
            w.put(&[0x24, self.channel])?;
            w.u16(
                u16::try_from(self.body.len())
                    .map_err(|_| invalid(NAME, "interleaved frame too long"))?,
            )?;
            w.put(&self.body)?;
            return Ok(w.bytes);
        }
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
        if b.first() == Some(&0x24) {
            let mut r = Reader::new(NAME, &b);
            r.u8()?;
            let channel = r.u8()?;
            let len = r.u16()? as usize;
            let body = Bytes::copy_from_slice(r.take(len)?);
            r.finish()?;
            return Ok(Self {
                interleaved: true,
                channel,
                body,
                ..Self::default()
            });
        }
        let (start_line, headers, body) = super::text_message::parse(NAME, &b)?;
        let text =
            std::str::from_utf8(&start_line).map_err(|_| invalid(NAME, "invalid start line"))?;
        let parts: Vec<_> = text.splitn(3, ' ').collect();
        if parts.len() != 3
            || !(parts[0] == "RTSP/1.0"
                && parts[1].len() == 3
                && parts[1].bytes().all(|b| b.is_ascii_digit())
                || parts[2] == "RTSP/1.0"
                    && !parts[0].is_empty()
                    && parts[0]
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b == b'-'))
        {
            return Err(unsupported(NAME, "unsupported start line or version"));
        }
        Ok(Self {
            start_line,
            headers,
            body,
            ..Self::default()
        })
    }
}
