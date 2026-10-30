// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RTCP v2 compound SR/RR/SDES/BYE/APP envelopes and checked report counts. Report data retains original bytes.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const PACKETS: &[crate::layer::FieldSchema] = &[
    member("packet_type", field::Kind::Unsigned, &[]),
    member("count", field::Kind::Unsigned, &[]),
    member("data", field::Kind::Bytes, &[]),
    member("padding", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Rtcp {
    pub packets: Records,
}
crate::reflective_layer! {
 fn rtcp_schema() => { protocol: crate::layer::Id::new("rtcp"), name: "Rtcp" }
 impl Rtcp {
    "packets" => { kind: List, derived: false, required: false, description: "Ordered compound RTCP packets", children: PACKETS, reflect: packets },
 }
}
fn rtcp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if b.len() <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "packets",
            range: crate::layout::ByteRange::new(0, b.len()),
        });
    }
    fields
}
message_codec!(RtcpCodec, Rtcp, rtcp_schema, rtcp_layout_wire);

const NAME: &str = "rtcp";
impl Rtcp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.packets.0.is_empty() {
            return Err(invalid(NAME, "empty compound packet"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        for r in &self.packets.0 {
            let pt = u8::try_from(number(r, "packet_type", NAME)?)
                .map_err(|_| invalid(NAME, "packet type overflow"))?;
            let count = number(r, "count", NAME)?;
            if count > 31 {
                return Err(invalid(NAME, "count exceeds five bits"));
            }
            let body = data(r, "data", NAME)?;
            let padding = match r.get("padding") {
                Some(field::Value::Bytes(b)) => b.as_ref(),
                None => &[],
                _ => return Err(invalid(NAME, "invalid padding")),
            };
            if !padding.is_empty()
                && (padding.len() > 255 || padding.last().copied() != Some(padding.len() as u8))
            {
                return Err(invalid(NAME, "padding count mismatch"));
            }
            if (body.len() + padding.len()) % 4 != 0 {
                return Err(invalid(NAME, "packet must contain whole words"));
            }
            w.u8(128 | count as u8 | if padding.is_empty() { 0 } else { 32 })?;
            w.u8(pt)?;
            w.u16(
                u16::try_from((body.len() + padding.len()) / 4)
                    .map_err(|_| invalid(NAME, "packet too long"))?,
            )?;
            w.put(body)?;
            w.put(padding)?;
        }
        validate(&w.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        validate(&b)?;
        let mut r = Reader::new(NAME, &b);
        let mut packets = Records::default();
        while r.left() > 0 {
            let h = r.u8()?;
            let pt = r.u8()?;
            let n = usize::from(r.u16()?) * 4;
            let body = r.take(n)?;
            let pad = if h & 32 != 0 {
                *body.last().unwrap() as usize
            } else {
                0
            };
            packets.0.push(record([
                ("packet_type", pt.into()),
                ("count", (h & 31).into()),
                ("data", Bytes::copy_from_slice(&body[..n - pad]).into()),
                ("padding", Bytes::copy_from_slice(&body[n - pad..]).into()),
            ]));
        }
        Ok(Self { packets })
    }
}
fn validate(b: &[u8]) -> Result<(), Error> {
    if b.is_empty() {
        return Err(invalid(NAME, "empty compound packet"));
    }
    let mut r = Reader::new(NAME, b);
    let mut count = 0;
    while r.left() > 0 {
        count += 1;
        if count > MAX_RECORDS {
            return Err(invalid(NAME, "too many packets"));
        }
        let h = r.u8()?;
        let pt = r.u8()?;
        if h >> 6 != 2 {
            return Err(unsupported(NAME, "only RTCP v2"));
        }
        let n = usize::from(r.u16()?) * 4;
        let body = r.take(n)?;
        let pad = if h & 32 != 0 {
            let p = body.last().copied().unwrap_or(0) as usize;
            if p == 0 || p > n || r.left() != 0 {
                return Err(invalid(NAME, "invalid compound padding"));
            }
            p
        } else {
            0
        };
        let b = &body[..n - pad];
        let count = usize::from(h & 31);
        match pt {
            200 if b.len() < 24 + 24 * count => {
                return Err(invalid(NAME, "invalid sender reports"));
            }
            201 if b.len() < 4 + 24 * count => {
                return Err(invalid(NAME, "invalid receiver reports"));
            }
            202 => {
                let mut s = Reader::new(NAME, b);
                for _ in 0..count {
                    s.take(4)?;
                    loop {
                        let kind = s.u8()?;
                        if kind == 0 {
                            while !s.pos.is_multiple_of(4) {
                                s.u8()?;
                            }
                            break;
                        }
                        let len = s.u8()? as usize;
                        s.take(len)?;
                    }
                }
                s.finish()?;
            }
            203 => {
                if b.len() < count * 4 {
                    return Err(invalid(NAME, "short BYE"));
                }
                if b.len() > count * 4 && b.len() < count * 4 + 1 + usize::from(b[count * 4]) {
                    return Err(invalid(NAME, "short BYE reason"));
                }
            }
            204 if b.len() < 8 => return Err(invalid(NAME, "short APP")),
            200..=204 => {}
            _ => return Err(unsupported(NAME, "packet type outside SR/RR/SDES/BYE/APP")),
        }
    }
    Ok(())
}
