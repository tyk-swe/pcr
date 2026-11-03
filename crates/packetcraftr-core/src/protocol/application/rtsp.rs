// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RTSP/1.0 requests/responses with byte-preserving ordered headers and Content-Length bodies.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{Reader, Records, Writer, message_codec, record};
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
 fn rtsp_schema() => { protocol: crate::protocol::BuiltinProtocol::Rtsp.id(), name: "Rtsp" }
 impl Rtsp {
    "start_line" => { kind: Bytes, derived: false, required: false, description: "start line", reflect: start_line },
    "headers" => { kind: List, derived: false, required: false, description: "Ordered header fields retaining spaces and case", children: HEADERS, reflect: headers },
    "body" => { kind: Bytes, derived: false, required: false, description: "body", reflect: body },
    "interleaved" => { kind: Bool, derived: false, required: false, description: "interleaved", reflect: interleaved },
    "channel" => { kind: Unsigned, derived: false, required: false, description: "channel", reflect: channel },
 }
}
message_codec!(RtspCodec, Rtsp, rtsp_schema);

const NAME: &str = "rtsp";
impl Rtsp {
    /// Fields the framing mode leaves off the wire must keep their defaults, which is also what
    /// decoding produces, so encoding never silently discards a caller's value.
    fn reject_uncarried_fields(&self) -> Result<(), Error> {
        let Self {
            start_line,
            headers,
            body: _,
            interleaved,
            channel,
        } = self;
        let default = Self::default();
        let uncarried = if *interleaved {
            [
                ("start_line", *start_line != default.start_line),
                ("headers", *headers != default.headers),
            ]
            .into_iter()
            .find(|(_, changed)| *changed)
            .map(|(field, _)| ("interleaved RTSP frames", field))
        } else {
            (*channel != default.channel).then_some(("text RTSP messages", "channel"))
        };
        match uncarried {
            Some((mode, field)) => Err(invalid(NAME, format!("{mode} do not carry field {field}"))),
            None => Ok(()),
        }
    }
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        self.reject_uncarried_fields()?;
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
        Ok(b)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        if b.first() == Some(&0x24) {
            let mut r = Reader::new(NAME, &b);
            r.mark(3, 0..1);
            r.mark(4, 1..2);
            r.mark(2, 4..b.len());
            r.u8()?;
            let channel = r.u8()?;
            let len = r.u16()? as usize;
            let body = Bytes::copy_from_slice(r.take(len)?);
            r.finish()?;
            return Ok((
                Self {
                    interleaved: true,
                    channel,
                    body,
                    ..Self::default()
                },
                r.take_layouts(),
            ));
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
                ..Self::default()
            },
            fields,
        ))
    }
}
