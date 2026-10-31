// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RESP2 scalar and recursive array values, bounded to 16 levels and 4096 values.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const RESP_FIELDS: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Text, &[]),
    member("data", field::Kind::Any, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resp {
    pub value: RespValue,
}
impl Default for Resp {
    fn default() -> Self {
        Self {
            value: RespValue::Simple(Bytes::from_static(b"OK")),
        }
    }
}
crate::reflective_layer! {
 fn resp_schema() => { protocol: crate::layer::Id::new("resp"), name: "Resp" }
 impl Resp {
    "value" => { kind: Object, derived: false, required: false, description: "RESP2 value with kind and typed content", children: RESP_FIELDS, reflect: value },
 }
}
fn resp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if b.len() <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "value",
            range: crate::layout::ByteRange::new(0, b.len()),
        });
    }
    fields
}
message_codec!(RespCodec, Resp, resp_schema, resp_layout_wire);

const NAME: &str = "resp";
impl Resp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        let mut count = 0;
        self.value.encode(&mut w, 0, &mut count)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let mut count = 0;
        let value = RespValue::parse(&mut r, 0, &mut count)?;
        r.finish()?;
        Ok(Self { value })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RespValue {
    Simple(Bytes),
    Error(Bytes),
    Integer(i64),
    Bulk(Option<Bytes>),
    Array(Option<Vec<Self>>),
}
impl RespValue {
    fn encode(&self, w: &mut Writer, depth: usize, count: &mut usize) -> Result<(), Error> {
        *count += 1;
        if depth >= MAX_NESTING || *count > MAX_RECORDS {
            return Err(invalid(NAME, "value tree exceeds limit"));
        }
        match self {
            Self::Simple(b) | Self::Error(b) => {
                if b.iter().any(|v| matches!(*v, b'\r' | b'\n')) {
                    return Err(invalid(NAME, "line value contains newline"));
                }
                w.u8(if matches!(self, Self::Simple(_)) {
                    b'+'
                } else {
                    b'-'
                })?;
                w.put(b)?;
                w.put(b"\r\n")?;
            }
            Self::Integer(n) => {
                w.u8(b':')?;
                w.put(n.to_string().as_bytes())?;
                w.put(b"\r\n")?;
            }
            Self::Bulk(None) => w.put(b"$-1\r\n")?,
            Self::Array(None) => w.put(b"*-1\r\n")?,
            Self::Bulk(Some(b)) => {
                w.u8(b'$')?;
                w.put(b.len().to_string().as_bytes())?;
                w.put(b"\r\n")?;
                w.put(b)?;
                w.put(b"\r\n")?;
            }
            Self::Array(Some(a)) => {
                w.u8(b'*')?;
                w.put(a.len().to_string().as_bytes())?;
                w.put(b"\r\n")?;
                for v in a {
                    v.encode(w, depth + 1, count)?;
                }
            }
        }
        Ok(())
    }
    fn parse(r: &mut Reader<'_>, depth: usize, count: &mut usize) -> Result<Self, Error> {
        *count += 1;
        if depth >= MAX_NESTING || *count > MAX_RECORDS {
            return Err(invalid(NAME, "value tree exceeds limit"));
        }
        let tag = r.u8()?;
        let len = r.bytes[r.pos..]
            .windows(2)
            .position(|v| v == b"\r\n")
            .ok_or_else(|| invalid(NAME, "unterminated value"))?;
        let line = r.take(len)?;
        r.take(2)?;
        if tag == b'+' || tag == b'-' {
            if line.iter().any(|byte| matches!(*byte, b'\r' | b'\n')) {
                return Err(invalid(NAME, "line value contains an embedded newline"));
            }
            return Ok(if tag == b'+' {
                Self::Simple(Bytes::copy_from_slice(line))
            } else {
                Self::Error(Bytes::copy_from_slice(line))
            });
        }
        let n = std::str::from_utf8(line)
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or_else(|| invalid(NAME, "invalid number"))?;
        if n.to_string().as_bytes() != line {
            return Err(unsupported(NAME, "noncanonical number"));
        }
        match tag {
            b':' => Ok(Self::Integer(n)),
            b'$' if n == -1 => Ok(Self::Bulk(None)),
            b'*' if n == -1 => Ok(Self::Array(None)),
            b'$' if n >= 0 => {
                let b = Bytes::copy_from_slice(
                    r.take(usize::try_from(n).map_err(|_| invalid(NAME, "length overflow"))?)?,
                );
                if r.take(2)? != b"\r\n" {
                    return Err(invalid(NAME, "bulk value missing CRLF"));
                }
                Ok(Self::Bulk(Some(b)))
            }
            b'*' if n >= 0 && n <= MAX_RECORDS as i64 => {
                let mut a = Vec::new();
                for _ in 0..n {
                    a.push(Self::parse(r, depth + 1, count)?);
                }
                Ok(Self::Array(Some(a)))
            }
            _ => Err(invalid(NAME, "invalid RESP2 value")),
        }
    }
    fn value(&self) -> field::Value {
        let (kind, value) = match self {
            Self::Simple(b) => ("simple", field::Value::Bytes(b.clone())),
            Self::Error(b) => ("error", field::Value::Bytes(b.clone())),
            Self::Integer(n) => ("integer", field::Value::Signed(*n)),
            Self::Bulk(Some(b)) => ("bulk", field::Value::Bytes(b.clone())),
            Self::Bulk(None) => ("null_bulk", field::Value::Bytes(Bytes::new())),
            Self::Array(None) => ("null_array", field::Value::List(vec![])),
            Self::Array(Some(a)) => (
                "array",
                field::Value::List(a.iter().map(Self::value).collect()),
            ),
        };
        field::Value::Object(record([
            ("kind", field::Value::Text(kind.into())),
            ("data", value),
        ]))
    }
    fn from_value(
        value: field::Value,
        depth: usize,
        count: &mut usize,
    ) -> Result<Self, crate::layer::Refusal> {
        use crate::layer::Refusal;
        *count += 1;
        if depth >= MAX_NESTING || *count > MAX_RECORDS {
            return Err(Refusal::OutOfRange);
        }
        let field::Value::Object(mut o) = value else {
            return Err(Refusal::WrongType("RESP value object"));
        };
        let Some(field::Value::Text(k)) = o.remove("kind") else {
            return Err(Refusal::WrongType("kind"));
        };
        let v = o.remove("data").ok_or(Refusal::WrongType("data"))?;
        if !o.is_empty() {
            return Err(Refusal::WrongType("kind/data object"));
        }
        match (k.as_str(), v) {
            ("simple", field::Value::Bytes(b)) => Ok(Self::Simple(b)),
            ("error", field::Value::Bytes(b)) => Ok(Self::Error(b)),
            ("integer", field::Value::Signed(n)) => Ok(Self::Integer(n)),
            ("integer", field::Value::Unsigned(n)) => i64::try_from(n)
                .map(Self::Integer)
                .map_err(|_| Refusal::OutOfRange),
            ("bulk", field::Value::Bytes(b)) => Ok(Self::Bulk(Some(b))),
            ("null_bulk", field::Value::Bytes(b)) if b.is_empty() => Ok(Self::Bulk(None)),
            ("null_array", field::Value::List(v)) if v.is_empty() => Ok(Self::Array(None)),
            ("array", field::Value::List(v)) => Ok(Self::Array(Some(
                v.into_iter()
                    .map(|v| Self::from_value(v, depth + 1, count))
                    .collect::<Result<_, _>>()?,
            ))),
            _ => Err(Refusal::WrongType("matching RESP kind/data")),
        }
    }
}
impl crate::layer::ReflectiveField for RespValue {
    fn reflective_value(&self) -> field::Value {
        self.value()
    }
    fn set_reflective_value(&mut self, value: field::Value) -> Result<(), crate::layer::Refusal> {
        *self = Self::from_value(value, 0, &mut 0)?;
        Ok(())
    }
}
