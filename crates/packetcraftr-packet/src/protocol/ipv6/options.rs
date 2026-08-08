// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    expected_discriminator, invalid, make_layer, protocol, resolve_u8, truncated,
    validate_auto_raw_discriminator, validate_ipv6_routing_child, validate_raw_child_discriminator,
    wrong_layer,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopByHop {
    pub next_header: WireValue<u8>,
    pub options: Bytes,
}

impl Default for HopByHop {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            options: Bytes::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationOptions {
    pub next_header: WireValue<u8>,
    pub options: Bytes,
}

impl Default for DestinationOptions {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            options: Bytes::new(),
        }
    }
}

macro_rules! declare_options_layer {
    ($ty:ty, $schema:ident, $protocol:literal, $name:literal, $layout:ident) => {
        reflective_layer! {
            fn $schema() => { protocol: protocol($protocol), name: $name }
            impl $ty {
                "next_header" => { kind: Unsigned, derived: true, required: false, description: "IPv6 next-header discriminator", get |layer| Some(reflect_get(&layer.next_header)), set |layer, value, name| reflect_set(&mut layer.next_header, $schema(), name, value), layout: (0, 1) },
                "options" => { kind: Bytes, derived: false, required: false, description: "Option bytes, padded to an eight-byte header boundary", get |layer| Some(reflect_get(&layer.options)), set |layer, value, name| reflect_set(&mut layer.options, $schema(), name, value), layout: (2, header_len) },
            }
            layout pub(crate) fn $layout(header_len: usize);
        }
    };
}

declare_options_layer!(
    HopByHop,
    hop_schema,
    "ipv6_hop_by_hop",
    "IPv6 Hop-by-Hop Options",
    hop_layout
);
declare_options_layer!(
    DestinationOptions,
    destination_schema,
    "ipv6_destination_options",
    "IPv6 Destination Options",
    destination_layout
);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HopByHopCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DestinationOptionsCodec;

fn encode_options<L>(
    name: &str,
    layer: &L,
    next_header: &WireValue<u8>,
    options: &Bytes,
    layout: fn(usize) -> Vec<crate::layout::FieldLayout>,
    context: &LayerEncodeContext<'_>,
) -> Result<EncodedLayer, CodecError>
where
    L: Layer + Clone + 'static,
{
    let expectation = expected_discriminator(name, context, 59_u8);
    let mut diagnostics = Vec::new();
    validate_auto_raw_discriminator(name, "next_header", next_header, context, &mut diagnostics)?;
    let (next, _) = resolve_u8(
        name,
        "next_header",
        next_header,
        expectation,
        context.mode,
        &mut diagnostics,
    )?;
    validate_raw_child_discriminator(name, u64::from(next), context, &mut diagnostics)?;
    validate_ipv6_routing_child(name, next, context, &mut diagnostics)?;
    let unpadded = options
        .len()
        .checked_add(2)
        .ok_or_else(|| invalid(name, "option length overflow"))?;
    let header_len = unpadded
        .checked_add((8 - unpadded % 8) % 8)
        .ok_or_else(|| invalid(name, "option padding overflow"))?;
    if header_len > 2_048 {
        return Err(invalid(
            name,
            "options header exceeds 2048-byte secure default",
        ));
    }
    let hdr_ext_len = u8::try_from(header_len / 8 - 1)
        .map_err(|_| invalid(name, "options header length cannot be represented"))?;
    let mut prefix = vec![0u8; header_len];
    prefix[0] = next;
    prefix[1] = hdr_ext_len;
    prefix[2..2 + options.len()].copy_from_slice(options);
    let mut materialized = layer.clone_box();
    materialized.set_field("next_header", FieldValue::Unsigned(u64::from(next)))?;
    materialized.set_field(
        "options",
        FieldValue::Bytes(Bytes::copy_from_slice(&prefix[2..header_len])),
    )?;
    Ok(EncodedLayer {
        prefix,
        suffix: Vec::new(),
        materialized,
        fields: layout(header_len),
        diagnostics,
    })
}

fn decode_options<L>(
    name: &str,
    input: &[u8],
    make: impl FnOnce(u8, Bytes) -> L,
    layout: fn(usize) -> Vec<crate::layout::FieldLayout>,
) -> Result<DecodedLayerValue, CodecError>
where
    L: Layer + 'static,
{
    if input.len() < 8 {
        return Err(truncated(name, 8, input.len()));
    }
    let header_len = (usize::from(input[1]) + 1)
        .checked_mul(8)
        .ok_or_else(|| invalid(name, "header length overflow"))?;
    if input.len() < header_len {
        return Err(truncated(name, header_len, input.len()));
    }
    Ok(DecodedLayerValue {
        layer: Box::new(make(
            input[0],
            Bytes::copy_from_slice(&input[2..header_len]),
        )),
        consumed: header_len,
        payload_offset: header_len,
        payload_len: input.len() - header_len,
        next: vec![Discriminator(u64::from(input[0]))],
        fields: layout(header_len),
        diagnostics: Vec::new(),
        stop: input.len() == header_len,
        network: None,
    })
}

impl LayerCodec for HopByHopCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6_hop_by_hop")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<HopByHop>()
            .ok_or_else(|| wrong_layer("ipv6_hop_by_hop", layer))?;
        encode_options(
            "ipv6_hop_by_hop",
            layer,
            &layer.next_header,
            &layer.options,
            hop_layout,
            context,
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_options(
            "ipv6_hop_by_hop",
            input,
            |next, options| HopByHop {
                next_header: WireValue::Exact(next),
                options,
            },
            hop_layout,
        )
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(HopByHop::default(), fields)
    }
}

impl LayerCodec for DestinationOptionsCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6_destination_options")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<DestinationOptions>()
            .ok_or_else(|| wrong_layer("ipv6_destination_options", layer))?;
        encode_options(
            "ipv6_destination_options",
            layer,
            &layer.next_header,
            &layer.options,
            destination_layout,
            context,
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_options(
            "ipv6_destination_options",
            input,
            |next, options| DestinationOptions {
                next_header: WireValue::Exact(next),
                options,
            },
            destination_layout,
        )
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(DestinationOptions::default(), fields)
    }
}
