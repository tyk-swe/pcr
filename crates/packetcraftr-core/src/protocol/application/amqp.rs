// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! AMQP 0-9-1 framing. Method argument bytes and content properties retain their wire encoding; frame_type=0 builds the protocol preface.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Amqp {
    pub frame_type: u8,
    pub channel: u16,
    pub class_id: u16,
    pub method_id: u16,
    pub payload: Bytes,
}
impl Default for Amqp {
    fn default() -> Self {
        Self {
            frame_type: 8,
            channel: 0,
            class_id: 0,
            method_id: 0,
            payload: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn amqp_schema() => { protocol: crate::layer::Id::new("amqp"), name: "Amqp" }
 impl Amqp {
    "frame_type" => { kind: Unsigned, derived: false, required: false, description: "frame type", reflect: frame_type },
    "channel" => { kind: Unsigned, derived: false, required: false, description: "channel", reflect: channel },
    "class_id" => { kind: Unsigned, derived: false, required: false, description: "class id", reflect: class_id },
    "method_id" => { kind: Unsigned, derived: false, required: false, description: "method id", reflect: method_id },
    "payload" => { kind: Bytes, derived: false, required: false, description: "payload", reflect: payload },
 }
 layout fn amqp_layout();
}
fn amqp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    if b.starts_with(b"AMQP") {
        return Vec::new();
    }
    let _ = amqp_layout();
    let mut fields = Vec::new();
    if !b.is_empty() {
        fields.push(crate::layout::FieldLayout {
            name: "frame_type",
            range: crate::layout::ByteRange::new(0, 1),
        });
    }
    if 3 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "channel",
            range: crate::layout::ByteRange::new(1, 3),
        });
    }
    fields
}
message_codec!(AmqpCodec, Amqp, amqp_schema, amqp_layout_wire);

const NAME: &str = "amqp";
impl Amqp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        if self.frame_type == 0 {
            w.put(b"AMQP\0\0\x09\x01")?;
            return Ok(w.bytes);
        }
        if !matches!(self.frame_type, 1 | 2 | 3 | 8) {
            return Err(unsupported(NAME, "unsupported frame type"));
        }
        let size = self
            .payload
            .len()
            .checked_add(if self.frame_type == 1 { 4 } else { 0 })
            .ok_or_else(|| invalid(NAME, "length overflow"))?;
        if self.frame_type == 8 && (size != 0 || self.channel != 0) {
            return Err(invalid(NAME, "invalid heartbeat"));
        }
        w.u8(self.frame_type)?;
        w.u16(self.channel)?;
        w.u32(u32::try_from(size).map_err(|_| invalid(NAME, "frame too long"))?)?;
        if self.frame_type == 1 {
            w.u16(self.class_id)?;
            w.u16(self.method_id)?;
        }
        w.put(&self.payload)?;
        w.u8(0xce)?;
        if self.frame_type == 2 {
            validate_content_header(&self.payload)?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        if b.starts_with(b"AMQP") {
            return if b.as_ref() == b"AMQP\0\0\x09\x01" {
                Ok(Self {
                    frame_type: 0,
                    ..Self::default()
                })
            } else {
                Err(unsupported(NAME, "only AMQP 0-9-1 is supported"))
            };
        }
        let mut r = Reader::new(NAME, &b);
        let mut s = Self {
            frame_type: r.u8()?,
            channel: r.u16()?,
            ..Self::default()
        };
        let len = r.u32()? as usize;
        if !matches!(s.frame_type, 1 | 2 | 3 | 8) {
            return Err(unsupported(NAME, "unsupported frame type"));
        }
        let payload = r.take(len)?;
        if r.u8()? != 0xce {
            return Err(invalid(NAME, "invalid frame terminator"));
        }
        r.finish()?;
        if s.frame_type == 8 && (len != 0 || s.channel != 0) {
            return Err(invalid(NAME, "invalid heartbeat"));
        }
        if s.frame_type == 1 {
            let mut p = Reader::new(NAME, payload);
            s.class_id = p.u16()?;
            s.method_id = p.u16()?;
            s.payload = Bytes::copy_from_slice(p.rest());
        } else {
            if s.frame_type == 2 {
                validate_content_header(payload)?;
            }
            s.payload = Bytes::copy_from_slice(payload);
        }
        Ok(s)
    }
}

fn validate_content_header(payload: &[u8]) -> Result<(), Error> {
    let mut reader = Reader::new(NAME, payload);
    reader.take(12)?;
    // Every content header has at least one flags word; bit zero continues the list.
    while reader.u16()? & 1 != 0 {}
    Ok(())
}
