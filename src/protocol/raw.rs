// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    expression::decode_hex,
    field::FieldValue,
    layer::{Layer, MalformedLayer, Padding, ProtocolId, Raw},
};

use super::common::{
    ensure_encode_budget, field_layout, invalid, make_layer, protocol, wrong_layer,
};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RawCodec;

impl LayerCodec for RawCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("raw")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Raw>()
            .ok_or_else(|| wrong_layer("raw", layer))?;
        ensure_encode_budget("raw", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = vec![field_layout("bytes", 0, layer.bytes.len())];
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(Raw::new(Bytes::copy_from_slice(input))),
            input.len(),
        );
        decoded.fields = vec![field_layout("bytes", 0, input.len())];
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Raw::default(), &raw_fields(fields, "raw")?)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PaddingCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct MalformedCodec;

impl LayerCodec for MalformedCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("malformed")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<MalformedLayer>()
            .ok_or_else(|| wrong_layer("malformed", layer))?;
        ensure_encode_budget("malformed", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = vec![field_layout("bytes", 0, layer.bytes.len())];
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
    ) -> Result<DecodedLayerValue, CodecError> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(MalformedLayer::new(
                None,
                Bytes::copy_from_slice(input),
                "explicit malformed root",
            )),
            input.len(),
        );
        decoded.fields = vec![field_layout("bytes", 0, input.len())];
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        let mut layer = MalformedLayer::new(None, Bytes::new(), "explicit malformed bytes");
        for (name, value) in fields {
            layer.set_field(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

impl LayerCodec for PaddingCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("padding")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Padding>()
            .ok_or_else(|| wrong_layer("padding", layer))?;
        ensure_encode_budget("padding", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = vec![field_layout("bytes", 0, layer.bytes.len())];
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(Padding::new(Bytes::copy_from_slice(input))),
            input.len(),
        );
        decoded.fields = vec![field_layout("bytes", 0, input.len())];
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Padding::default(), &raw_fields(fields, "padding")?)
    }
}

fn raw_fields(
    fields: &BTreeMap<String, FieldValue>,
    name: &str,
) -> Result<BTreeMap<String, FieldValue>, CodecError> {
    let mut normalized = fields.clone();
    let derived = match normalized.remove("hex") {
        Some(value) => {
            let FieldValue::Text(value) = value else {
                return Err(invalid(name, "hex must be a quoted hexadecimal string"));
            };
            Some(FieldValue::Bytes(decode_hex(&value)?))
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
