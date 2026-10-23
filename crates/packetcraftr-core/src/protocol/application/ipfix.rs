// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IPFIX v10 headers, templates and opaque data sets (RFC 7011). Template state and information-element interpretation are outside this codec.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const SETS: &[crate::layer::FieldSchema] = &[
    member("id", field::Kind::Unsigned, &[]),
    member("records", field::Kind::List, &[]),
    member("data", field::Kind::Bytes, &[]),
    member("padding", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Ipfix {
    pub export_time: u32,
    pub sequence: u32,
    pub observation_domain: u32,
    pub sets: Records,
}
crate::reflective_layer! {
 fn ipfix_schema() => { protocol: crate::layer::Id::new("ipfix"), name: "Ipfix" }
 impl Ipfix {
    "export_time" => { kind: Unsigned, derived: false, required: false, description: "export time", reflect: export_time },
    "sequence" => { kind: Unsigned, derived: false, required: false, description: "sequence", reflect: sequence },
    "observation_domain" => { kind: Unsigned, derived: false, required: false, description: "observation domain", reflect: observation_domain },
    "sets" => { kind: List, derived: false, required: false, description: "Template records or opaque data sets", children: SETS, reflect: sets },
 }
 layout fn ipfix_layout();
}
fn ipfix_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = ipfix_layout();
    let mut fields = Vec::new();
    if 8 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "export_time",
            range: crate::layout::ByteRange::new(4, 8),
        });
    }
    if 12 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "sequence",
            range: crate::layout::ByteRange::new(8, 12),
        });
    }
    if 16 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "observation_domain",
            range: crate::layout::ByteRange::new(12, 16),
        });
    }
    if b.len() <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "sets",
            range: crate::layout::ByteRange::new(16, b.len()),
        });
    }
    fields
}
message_codec!(IpfixCodec, Ipfix, ipfix_schema, ipfix_layout_wire);

const NAME: &str = "ipfix";
impl Ipfix {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let max = c.remaining_packet_bytes;
        let mut sets = Writer::new(NAME, max);
        for set in &self.sets.0 {
            let id = u16::try_from(number(set, "id", NAME)?)
                .map_err(|_| invalid(NAME, "set ID overflow"))?;
            let mut body = Writer::new(NAME, max);
            if matches!(id, 2 | 3) {
                let Some(field::Value::List(records)) = set.get("records") else {
                    return Err(invalid(NAME, "template set requires records"));
                };
                if records.len() > MAX_RECORDS {
                    return Err(invalid(NAME, "too many templates"));
                }
                for rec in records {
                    let field::Value::Object(rec) = rec else {
                        return Err(invalid(NAME, "invalid template"));
                    };
                    body.u16(
                        u16::try_from(number(rec, "template_id", NAME)?)
                            .map_err(|_| invalid(NAME, "template ID overflow"))?,
                    )?;
                    let Some(field::Value::List(fields)) = rec.get("fields") else {
                        return Err(invalid(NAME, "template requires fields"));
                    };
                    body.u16(
                        u16::try_from(fields.len())
                            .map_err(|_| invalid(NAME, "too many fields"))?,
                    )?;
                    if id == 3 {
                        body.u16(
                            u16::try_from(number(rec, "scope_count", NAME)?)
                                .map_err(|_| invalid(NAME, "scope count overflow"))?,
                        )?;
                    }
                    for f in fields {
                        let field::Value::Object(f) = f else {
                            return Err(invalid(NAME, "invalid field"));
                        };
                        let element = u16::try_from(number(f, "element_id", NAME)?)
                            .map_err(|_| invalid(NAME, "element ID overflow"))?;
                        body.u16(element)?;
                        body.u16(
                            u16::try_from(number(f, "length", NAME)?)
                                .map_err(|_| invalid(NAME, "field length overflow"))?,
                        )?;
                        if element & 0x8000 != 0 {
                            body.u32(
                                u32::try_from(number(f, "enterprise", NAME)?)
                                    .map_err(|_| invalid(NAME, "enterprise overflow"))?,
                            )?;
                        }
                    }
                }
                if let Some(field::Value::Bytes(pad)) = set.get("padding") {
                    if pad.len() > 3 {
                        return Err(invalid(NAME, "too much padding"));
                    }
                    body.put(pad)?;
                }
            } else {
                body.put(data(set, "data", NAME)?)?;
            }
            sets.u16(id)?;
            sets.u16(
                u16::try_from(body.bytes.len() + 4).map_err(|_| invalid(NAME, "set too long"))?,
            )?;
            sets.put(&body.bytes)?;
        }
        let mut w = Writer::new(NAME, max);
        w.u16(10)?;
        w.u16(
            u16::try_from(sets.bytes.len() + 16).map_err(|_| invalid(NAME, "message too long"))?,
        )?;
        w.u32(self.export_time)?;
        w.u32(self.sequence)?;
        w.u32(self.observation_domain)?;
        w.put(&sets.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        if r.u16()? != 10 {
            return Err(unsupported(NAME, "only IPFIX version 10"));
        }
        if r.u16()? as usize != b.len() {
            return Err(invalid(NAME, "message length mismatch"));
        }
        let mut s = Self {
            export_time: r.u32()?,
            sequence: r.u32()?,
            observation_domain: r.u32()?,
            ..Self::default()
        };
        let mut count = 0;
        while r.left() > 0 {
            count += 1;
            if count > MAX_RECORDS {
                return Err(invalid(NAME, "too many sets"));
            }
            let id = r.u16()?;
            let len = r.u16()?;
            if len < 4 {
                return Err(invalid(NAME, "short set"));
            }
            let b = r.take(len as usize - 4)?;
            let mut set = record([("id", id.into())]);
            if matches!(id, 2 | 3) {
                let mut p = Reader::new(NAME, b);
                let mut records = Vec::new();
                while p.left() >= if id == 2 { 4 } else { 6 } {
                    count += 1;
                    if count > MAX_RECORDS {
                        return Err(invalid(NAME, "too many templates"));
                    }
                    let tid = p.u16()?;
                    let fields = p.u16()? as usize;
                    if fields > MAX_RECORDS - count {
                        return Err(invalid(NAME, "too many fields"));
                    }
                    count += fields;
                    let scope = if id == 3 { p.u16()? } else { 0 };
                    if scope as usize > fields {
                        return Err(invalid(NAME, "scope count exceeds fields"));
                    }
                    let mut f = Vec::new();
                    for _ in 0..fields {
                        let eid = p.u16()?;
                        let len = p.u16()?;
                        let mut rec = record([("element_id", eid.into()), ("length", len.into())]);
                        if eid & 0x8000 != 0 {
                            rec.insert("enterprise".into(), p.u32()?.into());
                        }
                        f.push(field::Value::Object(rec));
                    }
                    records.push(field::Value::Object(record([
                        ("template_id", tid.into()),
                        ("scope_count", scope.into()),
                        ("fields", field::Value::List(f)),
                    ])));
                }
                if p.left() > 3 {
                    return Err(invalid(NAME, "truncated template"));
                }
                set.insert("records".into(), field::Value::List(records));
                set.insert("padding".into(), Bytes::copy_from_slice(p.rest()).into());
            } else {
                set.insert("data".into(), Bytes::copy_from_slice(b).into());
            }
            s.sets.0.push(set);
        }
        Ok(s)
    }
}
