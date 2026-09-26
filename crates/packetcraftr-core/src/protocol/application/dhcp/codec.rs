// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Wire helpers and layer-codec steps that the DHCPv4 and DHCPv6 codecs share.

use std::collections::BTreeMap;

use bytes::Bytes;

use super::{Error, Limit, Limits};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, Raw, raw_layout},
    layout::FieldLayout,
    protocol::common::{invalid, rejected, typed_layer},
};

/// A complete DHCP message that fills its UDP payload and retains its wire.
pub(super) trait Message: Layer + Default + Sized + 'static {
    const NAME: &'static str;

    fn decode_wire(wire: Bytes) -> Result<Self, Error>;

    fn encode_wire(&self, limits: Limits) -> Result<Bytes, Error>;

    fn layout() -> Vec<FieldLayout>;
}

pub(super) fn encode<M: Message>(
    layer: &dyn Layer,
    payload: &[u8],
    context: &LayerEncodeContext<'_>,
) -> Result<EncodedLayer, crate::codec::Error> {
    if !payload.is_empty() {
        return Err(invalid(M::NAME, "DHCP is a complete UDP payload"));
    }
    let layer = typed_layer::<M>(M::NAME, layer)?;
    let wire = layer
        .encode_wire(Limits {
            max_message_bytes: context.remaining_packet_bytes,
            ..Default::default()
        })
        .map_err(|error| rejected(M::NAME, error))?;
    let normalized = M::decode_wire(wire.clone()).map_err(|error| rejected(M::NAME, error))?;
    Ok(EncodedLayer::header(wire.to_vec(), Box::new(normalized)).with_fields(M::layout()))
}

/// Keeps a payload that cannot be this message as raw bytes.
pub(super) fn raw(input: Bytes) -> DecodedLayer {
    let mut raw = DecodedLayer::terminal(Box::new(Raw::new(input.clone())), input.len());
    raw.fields = raw_layout(input.len());
    raw
}

pub(super) fn decode<M: Message>(input: Bytes) -> Result<DecodedLayer, crate::codec::Error> {
    let layer = M::decode_wire(input.clone()).map_err(|error| rejected(M::NAME, error))?;
    let mut decoded = DecodedLayer::terminal(Box::new(layer), input.len());
    decoded.fields = M::layout();
    Ok(decoded)
}

pub(super) fn make_layer<M: Message>(
    fields: &BTreeMap<String, FieldValue>,
) -> Result<Box<dyn Layer>, crate::codec::Error> {
    let mut layer = match fields.get("wire") {
        Some(FieldValue::Bytes(wire)) => {
            M::decode_wire(wire.clone()).map_err(|error| rejected(M::NAME, error))?
        }
        Some(_) => return Err(invalid(M::NAME, "wire must be retained bytes")),
        None => M::default(),
    };
    for (name, value) in fields {
        if name == "wire" || layer.field(name).as_ref() == Some(value) {
            continue;
        }
        crate::protocol::common::set_document_field(&mut layer, name, value.clone())?;
    }
    if fields.contains_key("options")
        && let Some(message_type) = fields.get("message_type")
        && layer.field("message_type").as_ref() != Some(message_type)
    {
        return Err(invalid(
            M::NAME,
            "message_type conflicts with supplied options",
        ));
    }
    Ok(Box::new(layer))
}

pub(super) struct Budget {
    pub(super) limits: Limits,
    options: usize,
}
impl Budget {
    pub(super) fn new(limits: Limits, length: usize) -> Result<Self, Error> {
        let limits = Limits {
            max_message_bytes: limits.max_message_bytes.min(65_535),
            max_options: limits.max_options.min(4096),
            max_nesting: limits.max_nesting.min(8),
        };
        if length > limits.max_message_bytes {
            return Err(Error::Limit(Limit::MessageBytes));
        }
        Ok(Self { limits, options: 0 })
    }
    pub(super) fn option(&mut self, depth: usize) -> Result<(), Error> {
        if depth > self.limits.max_nesting {
            return Err(Error::Limit(Limit::OptionNesting));
        }
        if self.options >= self.limits.max_options {
            return Err(Error::Limit(Limit::OptionCount));
        }
        self.options += 1;
        Ok(())
    }
}
pub(super) fn take(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], Error> {
    bytes
        .get(offset..offset.saturating_add(length))
        .ok_or(Error::Truncated {
            offset,
            needed: length,
            available: bytes.len().saturating_sub(offset),
        })
}
pub(super) fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        take(bytes, offset, 2)?.try_into().expect("two bytes"),
    ))
}
pub(super) fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        take(bytes, offset, 4)?.try_into().expect("four bytes"),
    ))
}
pub(super) fn extend(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), Error> {
    if output.len().saturating_add(bytes.len()) > maximum {
        return Err(Error::Limit(Limit::EncodedBytes));
    }
    output.extend_from_slice(bytes);
    Ok(())
}
