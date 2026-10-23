// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DTLS 1.2 (RFC 6347) records and epoch-zero handshake fragments. Encrypted epochs remain opaque.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const HANDSHAKES: &[crate::layer::FieldSchema] = &[
    member("message_type", field::Kind::Unsigned, &[]),
    member("length", field::Kind::Unsigned, &[]),
    member("message_sequence", field::Kind::Unsigned, &[]),
    member("offset", field::Kind::Unsigned, &[]),
    member("data", field::Kind::Bytes, &[]),
];
const RECORDS: &[crate::layer::FieldSchema] = &[
    member("content_type", field::Kind::Unsigned, &[]),
    member("epoch", field::Kind::Unsigned, &[]),
    member("sequence", field::Kind::Unsigned, &[]),
    member("handshakes", field::Kind::List, HANDSHAKES),
    member("data", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Dtls {
    pub records: Records,
}
crate::reflective_layer! {
 fn dtls_schema() => { protocol: crate::layer::Id::new("dtls"), name: "Dtls" }
 impl Dtls {
    "records" => { kind: List, derived: false, required: false, description: "DTLS records and plaintext handshake fragment envelopes", children: RECORDS, reflect: records },
 }
 layout fn dtls_layout();
}
fn dtls_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = dtls_layout();
    let mut fields = Vec::new();
    if b.len() <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "records",
            range: crate::layout::ByteRange::new(0, b.len()),
        });
    }
    fields
}
message_codec!(DtlsCodec, Dtls, dtls_schema, dtls_layout_wire);

const NAME: &str = "dtls";
fn u24(r: &mut Reader<'_>) -> Result<u32, Error> {
    let b = r.take(3)?;
    Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}
fn put24(w: &mut Writer, v: u64) -> Result<(), Error> {
    if v > 0xffffff {
        return Err(invalid(NAME, "24-bit field overflow"));
    }
    w.put(&(v as u32).to_be_bytes()[1..])
}
impl Dtls {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.records.0.is_empty() {
            return Err(invalid(NAME, "empty DTLS datagram"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        for r in &self.records.0 {
            let kind = u8::try_from(number(r, "content_type", NAME)?)
                .map_err(|_| invalid(NAME, "content type overflow"))?;
            let epoch = u16::try_from(number(r, "epoch", NAME)?)
                .map_err(|_| invalid(NAME, "epoch overflow"))?;
            let seq = number(r, "sequence", NAME)?;
            if seq > 0xffffffffffff {
                return Err(invalid(NAME, "sequence overflow"));
            }
            let mut p = Writer::new(NAME, c.remaining_packet_bytes);
            if kind == 22 && epoch == 0 {
                let Some(field::Value::List(v)) = r.get("handshakes") else {
                    return Err(invalid(NAME, "handshake records require fragments"));
                };
                for h in v {
                    let field::Value::Object(h) = h else {
                        return Err(invalid(NAME, "invalid fragment"));
                    };
                    let b = data(h, "data", NAME)?;
                    let len = number(h, "length", NAME)?;
                    let offset = number(h, "offset", NAME)?;
                    if len > 0xffffff || offset > 0xffffff {
                        return Err(invalid(NAME, "24-bit field overflow"));
                    }
                    if offset
                        .checked_add(b.len() as u64)
                        .is_none_or(|end| end > len)
                    {
                        return Err(invalid(NAME, "fragment exceeds message"));
                    }
                    p.u8(u8::try_from(number(h, "message_type", NAME)?)
                        .map_err(|_| invalid(NAME, "handshake type overflow"))?)?;
                    put24(&mut p, len)?;
                    p.u16(
                        u16::try_from(number(h, "message_sequence", NAME)?)
                            .map_err(|_| invalid(NAME, "handshake sequence overflow"))?,
                    )?;
                    put24(&mut p, offset)?;
                    put24(&mut p, b.len() as u64)?;
                    p.put(b)?;
                }
            } else {
                p.put(data(r, "data", NAME)?)?;
            }
            w.u8(kind)?;
            w.u16(0xfefd)?;
            w.u16(epoch)?;
            w.put(&seq.to_be_bytes()[2..])?;
            w.u16(u16::try_from(p.bytes.len()).map_err(|_| invalid(NAME, "record too long"))?)?;
            w.put(&p.bytes)?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        if b.is_empty() {
            return Err(invalid(NAME, "empty datagram"));
        }
        let mut r = Reader::new(NAME, &b);
        let mut records = Records::default();
        let mut nodes = 0;
        while r.left() > 0 {
            nodes += 1;
            if nodes > MAX_RECORDS {
                return Err(invalid(NAME, "too many records"));
            }
            let kind = r.u8()?;
            if !matches!(kind, 20..=24) {
                return Err(unsupported(NAME, "unknown content type"));
            }
            if r.u16()? != 0xfefd {
                return Err(unsupported(NAME, "only DTLS 1.2"));
            }
            let epoch = r.u16()?;
            let seq = r.take(6)?;
            let sequence =
                u64::from_be_bytes([0, 0, seq[0], seq[1], seq[2], seq[3], seq[4], seq[5]]);
            let len = r.u16()? as usize;
            let body = r.take(len)?;
            let mut item = record([
                ("content_type", kind.into()),
                ("epoch", epoch.into()),
                ("sequence", sequence.into()),
            ]);
            if kind == 22 && epoch == 0 {
                let mut p = Reader::new(NAME, body);
                let mut fragments = Vec::new();
                while p.left() > 0 {
                    nodes += 1;
                    if nodes > MAX_RECORDS {
                        return Err(invalid(NAME, "too many fragments"));
                    }
                    let kind = p.u8()?;
                    let length = u24(&mut p)?;
                    let message_sequence = p.u16()?;
                    let offset = u24(&mut p)?;
                    let frag_len = u24(&mut p)?;
                    if offset.checked_add(frag_len).is_none_or(|end| end > length) {
                        return Err(invalid(NAME, "fragment exceeds message"));
                    }
                    let data = Bytes::copy_from_slice(p.take(frag_len as usize)?);
                    fragments.push(field::Value::Object(record([
                        ("message_type", kind.into()),
                        ("length", length.into()),
                        ("message_sequence", message_sequence.into()),
                        ("offset", offset.into()),
                        ("data", data.into()),
                    ])));
                }
                item.insert("handshakes".into(), field::Value::List(fragments));
            } else {
                item.insert("data".into(), Bytes::copy_from_slice(body).into());
            }
            records.0.push(item);
        }
        Ok(Self { records })
    }
}
