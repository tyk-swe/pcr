// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! CDP v1/v2 header, checksum and ordered TLVs. Unknown TLVs retain their original bytes.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const TLVS: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cdp {
    pub version: u8,
    pub ttl: u8,
    pub checksum: field::WireValue<u16>,
    pub tlvs: Records,
}
impl Default for Cdp {
    fn default() -> Self {
        Self {
            version: 2,
            ttl: 180,
            checksum: field::WireValue::Auto,
            tlvs: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn cdp_schema() => { protocol: crate::layer::Id::new("cdp"), name: "Cdp" }
 impl Cdp {
    "version" => { kind: Unsigned, derived: false, required: false, description: "version", reflect: version },
    "ttl" => { kind: Unsigned, derived: false, required: false, description: "ttl", reflect: ttl },
    "checksum" => { kind: Unsigned, derived: true, required: false, description: "checksum", reflect: checksum },
    "tlvs" => { kind: List, derived: false, required: false, description: "Ordered CDP TLVs including unknown types", children: TLVS, reflect: tlvs },
 }
}
fn cdp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if !b.is_empty() {
        fields.push(crate::layout::FieldLayout {
            name: "version",
            range: crate::layout::ByteRange::new(0, 1),
        });
    }
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "ttl",
            range: crate::layout::ByteRange::new(1, 2),
        });
    }
    if 4 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "checksum",
            range: crate::layout::ByteRange::new(2, 4),
        });
    }
    if b.len() <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "tlvs",
            range: crate::layout::ByteRange::new(4, b.len()),
        });
    }
    fields
}
message_codec!(CdpCodec, Cdp, cdp_schema, cdp_layout_wire);

const NAME: &str = "cdp";
impl Cdp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if !matches!(self.version, 1 | 2) {
            return Err(unsupported(NAME, "unknown CDP version"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(self.version)?;
        w.u8(self.ttl)?;
        w.u16(0)?;
        for t in &self.tlvs.0 {
            let kind = u16::try_from(number(t, "kind", NAME)?)
                .map_err(|_| invalid(NAME, "TLV kind overflow"))?;
            let v = data(t, "value", NAME)?;
            w.u16(kind)?;
            w.u16(u16::try_from(v.len() + 4).map_err(|_| invalid(NAME, "TLV length overflow"))?)?;
            w.put(v)?;
        }
        let expected = cdp_checksum(&w.bytes);
        let value = match &self.checksum {
            field::WireValue::Auto => expected,
            field::WireValue::Exact(v) => *v,
            field::WireValue::Raw(v) if v.len() == 2 && c.mode == Mode::Permissive => {
                u16::from_be_bytes([v[0], v[1]])
            }
            _ => return Err(invalid(NAME, "invalid checksum value")),
        };
        if c.mode == Mode::Strict && value != expected {
            return Err(invalid(NAME, "CDP checksum mismatch"));
        }
        w.bytes[2..4].copy_from_slice(&value.to_be_bytes());
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let version = r.u8()?;
        let ttl = r.u8()?;
        let checksum = r.u16()?;
        if !matches!(version, 1 | 2) {
            return Err(unsupported(NAME, "unknown CDP version"));
        }
        if cdp_checksum(&b) != 0 {
            return Err(invalid(NAME, "CDP checksum mismatch"));
        }
        let mut tlvs = Records::default();
        while r.left() > 0 {
            if tlvs.0.len() == MAX_RECORDS {
                return Err(invalid(NAME, "too many TLVs"));
            }
            let kind = r.u16()?;
            let len = r.u16()?;
            if len < 4 {
                return Err(invalid(NAME, "short TLV"));
            }
            tlvs.0.push(record([
                ("kind", kind.into()),
                (
                    "value",
                    Bytes::copy_from_slice(r.take(len as usize - 4)?).into(),
                ),
            ]));
        }
        Ok(Self {
            version,
            ttl,
            checksum: field::WireValue::Exact(checksum),
            tlvs,
        })
    }
}
fn cdp_checksum(b: &[u8]) -> u16 {
    let mut sum = 0u64;
    let (chunks, remainder) = b.as_chunks::<2>();
    for p in chunks {
        sum += u64::from(u16::from_be_bytes([p[0], p[1]]));
    }
    if let Some(&v) = remainder.first() {
        // Cisco's legacy odd-byte checksum adjusts a sign-extended final byte.
        sum += if v & 0x80 != 0 {
            0xff00 + u64::from(v - 1)
        } else {
            u64::from(v)
        };
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
