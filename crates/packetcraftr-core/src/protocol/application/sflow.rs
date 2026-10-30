// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! sFlow v5 XDR flow/counter samples and nested record envelopes. Unknown enterprise formats and XDR padding are preserved.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const SAMPLE_RECORD: &[crate::layer::FieldSchema] = &[
    member("format", field::Kind::Unsigned, &[]),
    member("data", field::Kind::Bytes, &[]),
    member("padding", field::Kind::Bytes, &[]),
];
const SAMPLES: &[crate::layer::FieldSchema] = &[
    member("format", field::Kind::Unsigned, &[]),
    member("sequence", field::Kind::Unsigned, &[]),
    member("source_id", field::Kind::Unsigned, &[]),
    member("source_type", field::Kind::Unsigned, &[]),
    member("source_index", field::Kind::Unsigned, &[]),
    member("sampling_rate", field::Kind::Unsigned, &[]),
    member("sample_pool", field::Kind::Unsigned, &[]),
    member("drops", field::Kind::Unsigned, &[]),
    member("input_format", field::Kind::Unsigned, &[]),
    member("input", field::Kind::Unsigned, &[]),
    member("output_format", field::Kind::Unsigned, &[]),
    member("output", field::Kind::Unsigned, &[]),
    member("records", field::Kind::List, SAMPLE_RECORD),
    member("data", field::Kind::Bytes, &[]),
    member("padding", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sflow {
    pub agent_type: u32,
    pub agent_address: Bytes,
    pub sub_agent: u32,
    pub sequence: u32,
    pub uptime: u32,
    pub samples: Records,
}
impl Default for Sflow {
    fn default() -> Self {
        Self {
            agent_type: 1,
            agent_address: Bytes::from_static(&[0; 4]),
            sub_agent: 0,
            sequence: 0,
            uptime: 0,
            samples: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn sflow_schema() => { protocol: crate::layer::Id::new("sflow"), name: "Sflow" }
 impl Sflow {
    "agent_type" => { kind: Unsigned, derived: false, required: false, description: "agent type", reflect: agent_type },
    "agent_address" => { kind: Bytes, derived: false, required: false, description: "agent address", reflect: agent_address },
    "sub_agent" => { kind: Unsigned, derived: false, required: false, description: "sub agent", reflect: sub_agent },
    "sequence" => { kind: Unsigned, derived: false, required: false, description: "sequence", reflect: sequence },
    "uptime" => { kind: Unsigned, derived: false, required: false, description: "uptime", reflect: uptime },
    "samples" => { kind: List, derived: false, required: false, description: "Flow/counter sample records; unknown sample formats remain opaque", children: SAMPLES, reflect: samples },
 }
}
fn sflow_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if 8 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "agent_type",
            range: crate::layout::ByteRange::new(4, 8),
        });
    }
    fields
}
message_codec!(SflowCodec, Sflow, sflow_schema, sflow_layout_wire);

const NAME: &str = "sflow";
const FLOW: &[&str] = &[
    "sequence",
    "source_id",
    "sampling_rate",
    "sample_pool",
    "drops",
    "input",
    "output",
];
const COUNTER: &[&str] = &["sequence", "source_id"];
const EXP_FLOW: &[&str] = &[
    "sequence",
    "source_type",
    "source_index",
    "sampling_rate",
    "sample_pool",
    "drops",
    "input_format",
    "input",
    "output_format",
    "output",
];
const EXP_COUNTER: &[&str] = &["sequence", "source_type", "source_index"];
fn fields(format: u32) -> Option<&'static [&'static str]> {
    match format {
        1 => Some(FLOW),
        2 => Some(COUNTER),
        3 => Some(EXP_FLOW),
        4 => Some(EXP_COUNTER),
        _ => None,
    }
}
impl Sflow {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let max = c.remaining_packet_bytes;
        let mut w = Writer::new(NAME, max);
        w.u32(5)?;
        w.u32(self.agent_type)?;
        if self.agent_address.len()
            != match self.agent_type {
                1 => 4,
                2 => 16,
                _ => return Err(invalid(NAME, "unknown agent address type")),
            }
        {
            return Err(invalid(NAME, "agent address width mismatch"));
        }
        w.put(&self.agent_address)?;
        w.u32(self.sub_agent)?;
        w.u32(self.sequence)?;
        w.u32(self.uptime)?;
        w.u32(u32::try_from(self.samples.0.len()).map_err(|_| invalid(NAME, "too many samples"))?)?;
        for s in &self.samples.0 {
            let format = u32::try_from(number(s, "format", NAME)?)
                .map_err(|_| invalid(NAME, "format overflow"))?;
            let mut p = Writer::new(NAME, max);
            if let Some(keys) = fields(format) {
                for key in keys {
                    p.u32(
                        u32::try_from(number(s, key, NAME)?)
                            .map_err(|_| invalid(NAME, "sample field overflow"))?,
                    )?;
                }
                let Some(field::Value::List(records)) = s.get("records") else {
                    return Err(invalid(NAME, "sample requires records"));
                };
                p.u32(
                    u32::try_from(records.len()).map_err(|_| invalid(NAME, "too many records"))?,
                )?;
                for rec in records {
                    let field::Value::Object(rec) = rec else {
                        return Err(invalid(NAME, "invalid record"));
                    };
                    opaque(&mut p, rec)?;
                }
            } else {
                p.put(data(s, "data", NAME)?)?;
            }
            let mut item = record([
                ("format", format.into()),
                ("data", Bytes::from(p.bytes).into()),
            ]);
            if let Some(p) = s.get("padding") {
                item.insert("padding".into(), p.clone());
            }
            opaque(&mut w, &item)?;
        }
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        if r.u32()? != 5 {
            return Err(unsupported(NAME, "only sFlow v5"));
        }
        let agent_type = r.u32()?;
        let n = match agent_type {
            1 => 4,
            2 => 16,
            _ => return Err(unsupported(NAME, "agent address type")),
        };
        let mut s = Self {
            agent_type,
            agent_address: Bytes::copy_from_slice(r.take(n)?),
            sub_agent: r.u32()?,
            sequence: r.u32()?,
            uptime: r.u32()?,
            ..Self::default()
        };
        let count = r.u32()? as usize;
        if count > MAX_RECORDS {
            return Err(invalid(NAME, "too many samples"));
        }
        let mut nodes = count;
        for _ in 0..count {
            let mut sample = read_opaque(&mut r)?;
            let format = number(&sample, "format", NAME)? as u32;
            if let Some(keys) = fields(format) {
                let b = data(&sample, "data", NAME)?.to_vec();
                let mut p = Reader::new(NAME, &b);
                for key in keys {
                    sample.insert((*key).into(), p.u32()?.into());
                }
                let n = p.u32()? as usize;
                nodes += n;
                if nodes > MAX_RECORDS {
                    return Err(invalid(NAME, "too many records"));
                }
                let mut records = Vec::new();
                for _ in 0..n {
                    records.push(field::Value::Object(read_opaque(&mut p)?));
                }
                p.finish()?;
                sample.remove("data");
                sample.insert("records".into(), field::Value::List(records));
            }
            s.samples.0.push(sample);
        }
        r.finish()?;
        Ok(s)
    }
}
fn opaque(
    w: &mut Writer,
    r: &std::collections::BTreeMap<String, field::Value>,
) -> Result<(), Error> {
    let b = data(r, "data", NAME)?;
    w.u32(
        u32::try_from(number(r, "format", NAME)?).map_err(|_| invalid(NAME, "format overflow"))?,
    )?;
    w.u32(u32::try_from(b.len()).map_err(|_| invalid(NAME, "opaque too long"))?)?;
    w.put(b)?;
    let pad = (4 - b.len() % 4) % 4;
    if let Some(field::Value::Bytes(p)) = r.get("padding") {
        if p.len() != pad {
            return Err(invalid(NAME, "invalid XDR padding"));
        }
        w.put(p)?;
    } else {
        w.put(&[0; 3][..pad])?;
    }
    Ok(())
}
fn read_opaque(
    r: &mut Reader<'_>,
) -> Result<std::collections::BTreeMap<String, field::Value>, Error> {
    let format = r.u32()?;
    let n = r.u32()? as usize;
    let data = Bytes::copy_from_slice(r.take(n)?);
    let padding = Bytes::copy_from_slice(r.take((4 - n % 4) % 4)?);
    Ok(record([
        ("format", format.into()),
        ("data", data.into()),
        ("padding", padding.into()),
    ]))
}
