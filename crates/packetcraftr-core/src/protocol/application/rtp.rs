// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RTP version 2 (RFC 3550), including CSRC, extension and padding; media data remains opaque.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const CSRCS: &[crate::layer::FieldSchema] = &[member("ssrc", field::Kind::Unsigned, &[])];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rtp {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Records,
    pub has_extension: bool,
    pub extension_profile: u16,
    pub extension_data: Bytes,
    pub payload: Bytes,
    pub padding: Bytes,
}
impl Default for Rtp {
    fn default() -> Self {
        Self {
            marker: false,
            payload_type: 0,
            sequence: 0,
            timestamp: 0,
            ssrc: 0,
            csrcs: Records::default(),
            has_extension: false,
            extension_profile: 0,
            extension_data: Bytes::new(),
            payload: Bytes::new(),
            padding: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn rtp_schema() => { protocol: crate::layer::Id::new("rtp"), name: "Rtp" }
 impl Rtp {
    "marker" => { kind: Bool, derived: false, required: false, description: "marker", reflect: marker },
    "payload_type" => { kind: Unsigned, derived: false, required: false, description: "payload type", reflect: payload_type },
    "sequence" => { kind: Unsigned, derived: false, required: false, description: "sequence", reflect: sequence },
    "timestamp" => { kind: Unsigned, derived: false, required: false, description: "timestamp", reflect: timestamp },
    "ssrc" => { kind: Unsigned, derived: false, required: false, description: "ssrc", reflect: ssrc },
    "csrcs" => { kind: List, derived: false, required: false, description: "Contributing source identifiers", children: CSRCS, reflect: csrcs },
    "has_extension" => { kind: Bool, derived: false, required: false, description: "has extension", reflect: has_extension },
    "extension_profile" => { kind: Unsigned, derived: false, required: false, description: "extension profile", reflect: extension_profile },
    "extension_data" => { kind: Bytes, derived: false, required: false, description: "extension data", reflect: extension_data },
    "payload" => { kind: Bytes, derived: false, required: false, description: "payload", reflect: payload },
    "padding" => { kind: Bytes, derived: false, required: false, description: "padding", reflect: padding },
 }
 layout fn rtp_layout();
}
fn rtp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = rtp_layout();
    let mut fields = Vec::new();
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "marker",
            range: crate::layout::ByteRange::new(1, 2),
        });
    }
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "payload_type",
            range: crate::layout::ByteRange::new(1, 2),
        });
    }
    if 4 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "sequence",
            range: crate::layout::ByteRange::new(2, 4),
        });
    }
    if 8 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "timestamp",
            range: crate::layout::ByteRange::new(4, 8),
        });
    }
    if 12 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "ssrc",
            range: crate::layout::ByteRange::new(8, 12),
        });
    }
    fields
}
message_codec!(RtpCodec, Rtp, rtp_schema, rtp_layout_wire);

const NAME: &str = "rtp";
impl Rtp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.payload_type > 127 || self.csrcs.0.len() > 15 {
            return Err(invalid(NAME, "header field overflow"));
        }
        if !self.has_extension && !self.extension_data.is_empty() {
            return Err(invalid(NAME, "extension data without flag"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(0x80
            | if self.padding.is_empty() { 0 } else { 32 }
            | if self.has_extension { 16 } else { 0 }
            | self.csrcs.0.len() as u8)?;
        w.u8(if self.marker { 128 } else { 0 } | self.payload_type)?;
        w.u16(self.sequence)?;
        w.u32(self.timestamp)?;
        w.u32(self.ssrc)?;
        for r in &self.csrcs.0 {
            w.u32(
                u32::try_from(number(r, "ssrc", NAME)?)
                    .map_err(|_| invalid(NAME, "CSRC overflow"))?,
            )?;
        }
        if self.has_extension {
            if !self.extension_data.len().is_multiple_of(4) {
                return Err(invalid(NAME, "extension must be whole words"));
            }
            w.u16(self.extension_profile)?;
            w.u16(
                u16::try_from(self.extension_data.len() / 4)
                    .map_err(|_| invalid(NAME, "extension too long"))?,
            )?;
            w.put(&self.extension_data)?;
        }
        w.put(&self.payload)?;
        if !self.padding.is_empty() {
            if self.padding.len() > 255
                || self.padding.last().copied() != Some(self.padding.len() as u8)
            {
                return Err(invalid(NAME, "padding count mismatch"));
            }
            w.put(&self.padding)?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let h = r.u8()?;
        if h >> 6 != 2 {
            return Err(unsupported(NAME, "only RTP v2"));
        }
        let pt = r.u8()?;
        let mut s = Self {
            marker: pt & 128 != 0,
            payload_type: pt & 127,
            sequence: r.u16()?,
            timestamp: r.u32()?,
            ssrc: r.u32()?,
            has_extension: h & 16 != 0,
            ..Self::default()
        };
        for _ in 0..h & 15 {
            s.csrcs.0.push(record([("ssrc", r.u32()?.into())]));
        }
        if s.has_extension {
            s.extension_profile = r.u16()?;
            let len = usize::from(r.u16()?) * 4;
            s.extension_data = Bytes::copy_from_slice(r.take(len)?);
        }
        let remaining = r.rest();
        let pad = if h & 32 != 0 {
            let n = remaining.last().copied().unwrap_or(0) as usize;
            if n == 0 || n > remaining.len() {
                return Err(invalid(NAME, "invalid padding"));
            }
            n
        } else {
            0
        };
        s.payload = Bytes::copy_from_slice(&remaining[..remaining.len() - pad]);
        s.padding = Bytes::copy_from_slice(&remaining[remaining.len() - pad..]);
        Ok(s)
    }
}
