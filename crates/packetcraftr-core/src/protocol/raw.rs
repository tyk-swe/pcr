// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, Malformed, Padding, Raw},
};

use super::common::{ensure_encode_budget, invalid, make_layer, protocol, wrong_layer};

/// Parses hexadecimal raw bytes with optional `0x`, whitespace, colon, or dash separators.
pub fn parse_hex(input: &str) -> Result<Bytes, crate::codec::Error> {
    let protocol = crate::layer::Id::new("raw");
    let compact = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && *character != ':' && *character != '-'
        })
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return Err(crate::codec::Error::Invalid {
            protocol,
            message: "hex value must contain an even number of digits".to_owned(),
        });
    }
    let digits = compact.as_bytes();
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    let mut offset = 0_usize;
    while let Some(pair) = digits.get(offset..).and_then(<[u8]>::first_chunk::<2>) {
        let high = hex_nibble(pair[0]).ok_or_else(|| crate::codec::Error::Invalid {
            protocol: protocol.clone(),
            message: format!("invalid hex at byte {offset}"),
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| crate::codec::Error::Invalid {
            protocol: protocol.clone(),
            message: format!("invalid hex at byte {}", offset.saturating_add(1)),
        })?;
        bytes.push((high << 4) | low);
        offset = offset.saturating_add(2);
    }
    Ok(Bytes::from(bytes))
}

#[expect(
    clippy::arithmetic_side_effects,
    reason = "each arm bounds value to its own ASCII range, so the subtraction and the plus ten stay inside u8"
)]
fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RawCodec;

impl LayerCodec for RawCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("raw")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = layer
            .as_any()
            .downcast_ref::<Raw>()
            .ok_or_else(|| wrong_layer("raw", layer))?;
        ensure_encode_budget("raw", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = crate::layer::raw_layout(layer.bytes.len());
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(Raw::new(Bytes::copy_from_slice(input))),
            input.len(),
        );
        decoded.fields = crate::layer::raw_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Raw::default(), &raw_fields(fields, "raw")?)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PaddingCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct MalformedCodec;

impl LayerCodec for MalformedCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("malformed")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = layer
            .as_any()
            .downcast_ref::<Malformed>()
            .ok_or_else(|| wrong_layer("malformed", layer))?;
        ensure_encode_budget("malformed", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = crate::layer::malformed_layout(layer.bytes.len());
        encoded.diagnostics.push(Diagnostic::warning(
            "build.malformed_layer",
            format!("preserving explicitly malformed bytes: {}", layer.reason),
        ));
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(Malformed::new(
                None,
                Bytes::copy_from_slice(input),
                "explicit malformed root",
            )),
            input.len(),
        );
        decoded.fields = crate::layer::malformed_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        let mut layer = Malformed::new(None, Bytes::new(), "explicit malformed bytes");
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

impl LayerCodec for PaddingCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("padding")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = layer
            .as_any()
            .downcast_ref::<Padding>()
            .ok_or_else(|| wrong_layer("padding", layer))?;
        ensure_encode_budget("padding", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = crate::layer::padding_layout(layer.bytes.len());
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(Padding::new(Bytes::copy_from_slice(input))),
            input.len(),
        );
        decoded.fields = crate::layer::padding_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Padding::default(), &raw_fields(fields, "padding")?)
    }
}

fn raw_fields(
    fields: &BTreeMap<String, FieldValue>,
    name: &str,
) -> Result<BTreeMap<String, FieldValue>, crate::codec::Error> {
    let mut normalized = fields.clone();
    let derived = match normalized.remove("hex") {
        Some(value) => {
            let FieldValue::Text(value) = value else {
                return Err(invalid(name, "hex must be a quoted hexadecimal string"));
            };
            Some(FieldValue::Bytes(parse_hex(&value)?))
        }
        None => match normalized.remove("text") {
            Some(value) => {
                let FieldValue::Text(value) = value else {
                    return Err(invalid(name, "text must be a quoted string"));
                };
                Some(FieldValue::Bytes(Bytes::from(value.into_bytes())))
            }
            None => None,
        },
    };
    if let Some(value) = derived
        && normalized.insert("bytes".to_string(), value).is_some()
    {
        return Err(invalid(name, "bytes cannot be combined with hex or text"));
    }
    Ok(normalized)
}
