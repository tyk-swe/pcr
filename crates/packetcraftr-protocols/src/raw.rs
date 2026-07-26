// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, NativeLayerCodec, NativeLayerDecodeContext,
        NativeLayerEncodeContext,
    },
    diagnostic::Diagnostic,
    layer::{Layer, MalformedLayer, Padding, Raw},
};

use super::common::{ensure_encode_budget, make_layer, wrong_layer};

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RawCodec;

impl NativeLayerCodec for RawCodec {
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Raw>()
            .ok_or_else(|| wrong_layer("raw", layer))?;
        ensure_encode_budget("raw", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = packetcraftr_packet::layer::raw_layout(layer.bytes.len());
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(Raw::new(Bytes::copy_from_slice(input))),
            input.len(),
        );
        decoded.fields = packetcraftr_packet::layer::raw_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &packetcraftr_packet::layer::ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Raw::default(), fields)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PaddingCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct MalformedCodec;

impl NativeLayerCodec for MalformedCodec {
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<MalformedLayer>()
            .ok_or_else(|| wrong_layer("malformed", layer))?;
        ensure_encode_budget("malformed", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = packetcraftr_packet::layer::malformed_layout(layer.bytes.len());
        encoded.diagnostics.push(Diagnostic::warning(
            "build.malformed_layer",
            format!("preserving explicitly malformed bytes: {}", layer.reason),
        ));
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(MalformedLayer::new(
                None,
                Bytes::copy_from_slice(input),
                "explicit malformed root",
            )),
            input.len(),
        );
        decoded.fields = packetcraftr_packet::layer::malformed_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &packetcraftr_packet::layer::ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError> {
        let mut layer = MalformedLayer::new(None, Bytes::new(), "explicit malformed bytes");
        for (field, value) in fields.iter() {
            layer.set_field_by_id(&field.id, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

impl NativeLayerCodec for PaddingCodec {
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Padding>()
            .ok_or_else(|| wrong_layer("padding", layer))?;
        ensure_encode_budget("padding", layer.bytes.len(), context)?;
        let mut encoded = EncodedLayer::header(layer.bytes.to_vec(), Box::new(layer.clone()));
        encoded.fields = packetcraftr_packet::layer::padding_layout(layer.bytes.len());
        Ok(encoded)
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
        let mut decoded = DecodedLayerValue::terminal(
            Box::new(Padding::new(Bytes::copy_from_slice(input))),
            input.len(),
        );
        decoded.fields = packetcraftr_packet::layer::padding_layout(input.len());
        Ok(decoded)
    }

    fn make_layer(
        &self,
        fields: &packetcraftr_packet::layer::ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Padding::default(), fields)
    }
}
