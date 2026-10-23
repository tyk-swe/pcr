// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded wire primitives for message-oriented protocols.

use std::collections::BTreeMap;

use bytes::Bytes;

use super::common::{invalid, truncated};
use crate::{
    codec, field,
    layer::{ReflectiveField, Refusal},
};

/// Ordered records. Unknown record values remain bytes; duplicate kinds are retained.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Records(pub Vec<BTreeMap<String, field::Value>>);

pub(crate) const MAX_RECORDS: usize = 4096;
pub(crate) const MAX_NESTING: usize = 16;

impl ReflectiveField for Records {
    fn reflective_value(&self) -> field::Value {
        field::Value::List(self.0.iter().cloned().map(field::Value::Object).collect())
    }
    fn set_reflective_value(&mut self, value: field::Value) -> Result<(), Refusal> {
        let field::Value::List(values) = value else {
            return Err(Refusal::WrongType("list of objects"));
        };
        if values.len() > MAX_RECORDS {
            return Err(Refusal::OutOfRange);
        }
        let records = values
            .into_iter()
            .map(|v| match v {
                field::Value::Object(v) if v.len() <= 64 && v.values().all(|v| bounded(v, 0)) => {
                    Ok(v)
                }
                _ => Err(Refusal::WrongType("bounded object")),
            })
            .collect::<Result<_, _>>()?;
        self.0 = records;
        Ok(())
    }
}

fn bounded(value: &field::Value, depth: usize) -> bool {
    if depth >= MAX_NESTING {
        return false;
    }
    match value {
        field::Value::List(v) => v.len() <= MAX_RECORDS && v.iter().all(|v| bounded(v, depth + 1)),
        field::Value::Object(v) => v.len() <= 64 && v.values().all(|v| bounded(v, depth + 1)),
        _ => true,
    }
}

pub(crate) fn record<const N: usize>(
    fields: [(&str, field::Value); N],
) -> BTreeMap<String, field::Value> {
    fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}
pub(crate) fn number(
    r: &BTreeMap<String, field::Value>,
    key: &str,
    name: &'static str,
) -> Result<u64, codec::Error> {
    match r.get(key) {
        Some(field::Value::Unsigned(n)) => Ok(*n),
        _ => Err(invalid(name, format!("record requires unsigned {key}"))),
    }
}
pub(crate) fn data<'a>(
    r: &'a BTreeMap<String, field::Value>,
    key: &str,
    name: &'static str,
) -> Result<&'a [u8], codec::Error> {
    match r.get(key) {
        Some(field::Value::Bytes(b)) => Ok(b),
        Some(field::Value::Text(s)) => Ok(s.as_bytes()),
        _ => Err(invalid(name, format!("record requires bytes {key}"))),
    }
}

pub(crate) struct Reader<'a> {
    pub(crate) name: &'static str,
    pub(crate) bytes: &'a [u8],
    pub(crate) pos: usize,
}
impl<'a> Reader<'a> {
    pub(crate) fn new(name: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            name,
            bytes,
            pos: 0,
        }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], codec::Error> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| invalid(self.name, "length overflow"))?;
        let b = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| truncated(self.name, end, self.bytes.len()))?;
        self.pos = end;
        Ok(b)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, codec::Error> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, codec::Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, codec::Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    pub(crate) fn le16(&mut self) -> Result<u16, codec::Error> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }
    pub(crate) fn le32(&mut self) -> Result<u32, codec::Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let b = &self.bytes[self.pos..];
        self.pos = self.bytes.len();
        b
    }
    pub(crate) fn left(&self) -> usize {
        self.bytes.len() - self.pos
    }
    pub(crate) fn finish(self) -> Result<(), codec::Error> {
        if self.left() == 0 {
            Ok(())
        } else {
            Err(invalid(self.name, "unexpected trailing bytes"))
        }
    }
    pub(crate) fn bytes16(&mut self) -> Result<Bytes, codec::Error> {
        let n = usize::from(self.u16()?);
        Ok(Bytes::copy_from_slice(self.take(n)?))
    }
}

pub(crate) struct Writer {
    name: &'static str,
    max: usize,
    pub(crate) bytes: Vec<u8>,
}
impl Writer {
    pub(crate) fn new(name: &'static str, max: usize) -> Self {
        Self {
            name,
            max,
            bytes: Vec::new(),
        }
    }
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<(), codec::Error> {
        let n = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.max)
            .ok_or_else(|| invalid(self.name, "message exceeds byte budget"))?;
        self.bytes
            .try_reserve(n - self.bytes.len())
            .map_err(|_| invalid(self.name, "allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn u8(&mut self, v: u8) -> Result<(), codec::Error> {
        self.put(&[v])
    }
    pub(crate) fn u16(&mut self, v: u16) -> Result<(), codec::Error> {
        self.put(&v.to_be_bytes())
    }
    pub(crate) fn u32(&mut self, v: u32) -> Result<(), codec::Error> {
        self.put(&v.to_be_bytes())
    }
    pub(crate) fn le16(&mut self, v: u16) -> Result<(), codec::Error> {
        self.put(&v.to_le_bytes())
    }
    pub(crate) fn le32(&mut self, v: u32) -> Result<(), codec::Error> {
        self.put(&v.to_le_bytes())
    }
    pub(crate) fn bytes16(&mut self, v: &[u8]) -> Result<(), codec::Error> {
        self.u16(u16::try_from(v.len()).map_err(|_| invalid(self.name, "string too long"))?)?;
        self.put(v)
    }
}

/// Implement the common complete-message codec contract while retaining each protocol's parser.
macro_rules! message_codec {
    ($codec:ident, $ty:ident, $schema:ident, $layout:ident) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub(crate) struct $codec;
        impl crate::codec::Codec for $codec {
            fn protocol_id(&self) -> &'static crate::layer::Id {
                &$schema().protocol
            }
            fn published_schema(&self) -> Option<&'static crate::layer::Schema> {
                Some($schema())
            }
            fn accepts_decoded_protocol(&self, p: &crate::layer::Id) -> bool {
                p == self.protocol_id() || p.as_str() == "raw"
            }
            fn make_layer(
                &self,
                fields: &std::collections::BTreeMap<String, crate::field::Value>,
            ) -> Result<Box<dyn crate::layer::Layer>, crate::codec::Error> {
                crate::protocol::common::make_layer($ty::default(), fields)
            }
            fn encode(
                &self,
                layer: &dyn crate::layer::Layer,
                payload: &[u8],
                context: &crate::codec::EncodeContext<'_>,
            ) -> Result<crate::codec::Encoded, crate::codec::Error> {
                let name = $schema().protocol.as_str();
                if !payload.is_empty()
                    && context.child.is_none_or(|child| {
                        child.protocol_id() != self.protocol_id()
                            && !crate::protocol::common::child_is_opaque(child)
                    })
                {
                    return Err(crate::protocol::common::invalid(
                        name,
                        "complete message cannot have a child payload",
                    ));
                }
                let layer = crate::protocol::common::typed_layer::<$ty>(name, layer)?;
                let bytes = layer.encode_wire(context)?;
                crate::protocol::common::ensure_encode_budget(name, bytes.len(), context)?;
                let decoded_context = crate::codec::DecodeContext {
                    parent: None,
                    registry: context.registry,
                    network: crate::protocol::network::resolve_envelope(name, context).ok(),
                    hop_limit: None,
                    discriminator: None,
                };
                let mut diagnostics = Vec::new();
                let materialized = match $ty::parse_wire(
                    bytes::Bytes::copy_from_slice(&bytes),
                    &decoded_context,
                ) {
                    Ok(layer) => layer,
                    Err(error) if context.mode == crate::codec::Mode::Permissive => {
                        diagnostics.push(crate::diagnostic::Diagnostic::warning(
                            "build.message",
                            error.to_string(),
                        ));
                        layer.clone()
                    }
                    Err(error) => return Err(error),
                };
                let fields = $layout(&bytes);
                Ok(crate::codec::Encoded::header(bytes, Box::new(materialized))
                    .with_fields(fields)
                    .with_diagnostics(diagnostics))
            }
            fn decode(
                &self,
                input: bytes::Bytes,
                context: &crate::codec::DecodeContext<'_>,
            ) -> Result<crate::codec::Decoded, crate::codec::Error> {
                let name = $schema().protocol.as_str();
                let len =
                    match crate::protocol::framing::packet_length(name, &input, context.parent) {
                        Ok(n) => n,
                        Err(crate::codec::Error::Unsupported { .. }) => {
                            return Ok(crate::layer::Raw::decoded(input));
                        }
                        Err(e) => return Err(e),
                    };
                let wire = input.slice(..len);
                match $ty::parse_wire(wire, context) {
                    Ok(layer) => {
                        let mut result = crate::codec::Decoded::terminal(Box::new(layer), len);
                        result.fields = $layout(&input[..len]);
                        if input.len() > len {
                            result.payload_len = input.len() - len;
                            result.next = vec![crate::registry::Discriminator(0)];
                            result.stop = false;
                        }
                        Ok(result)
                    }
                    Err(crate::codec::Error::Unsupported { .. }) => {
                        Ok(crate::layer::Raw::decoded(input))
                    }
                    Err(e) => Err(e),
                }
            }
        }
    };
}
pub(crate) use message_codec;

pub(crate) fn checksum_value(
    name: &'static str,
    value: &field::WireValue<u16>,
    expected: u16,
    context: &codec::EncodeContext<'_>,
) -> Result<u16, codec::Error> {
    let v = match value {
        field::WireValue::Auto => expected,
        field::WireValue::Exact(v) => *v,
        field::WireValue::Raw(b) if b.len() == 2 && context.mode == codec::Mode::Permissive => {
            u16::from_be_bytes([b[0], b[1]])
        }
        _ => return Err(invalid(name, "invalid checksum field")),
    };
    if context.mode == codec::Mode::Strict && v != expected {
        return Err(invalid(name, "checksum mismatch"));
    }
    Ok(v)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod review_tests;
