// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{invalid, make_layer, protocol, truncated, typed_layer};

use super::resolve_next_header;

use crate::protocol::BuiltinProtocol;

const HOP_NAME: &str = BuiltinProtocol::Ipv6HopByHop.as_str();
const DESTINATION_NAME: &str = BuiltinProtocol::Ipv6DestinationOptions.as_str();

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
    ($ty:ty, $schema:ident, $protocol:expr, $name:literal, $layout:ident) => {
        reflective_layer! {
            fn $schema() => { protocol: protocol($protocol), name: $name }
            impl $ty {
                "next_header" => { kind: Unsigned, derived: true, required: false, description: "IPv6 next-header discriminator", reflect: next_header, layout: (0, 1) },
                "options" => { kind: Bytes, derived: false, required: false, description: "Option bytes, padded to an eight-byte header boundary", reflect: options, layout: (2, header_len) },
            }
            layout pub(crate) fn $layout(header_len: usize);
        }
    };
}

declare_options_layer!(
    HopByHop,
    hop_schema,
    HOP_NAME,
    "IPv6 Hop-by-Hop Options",
    hop_layout
);
declare_options_layer!(
    DestinationOptions,
    destination_schema,
    DESTINATION_NAME,
    "IPv6 Destination Options",
    destination_layout
);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HopByHopCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DestinationOptionsCodec;

fn encode_options(
    name: &'static str,
    next_header: &WireValue<u8>,
    options: &Bytes,
    layout: fn(usize) -> Vec<crate::layout::FieldLayout>,
    context: &LayerEncodeContext<'_>,
    materialize: impl FnOnce(WireValue<u8>, Bytes) -> Box<dyn Layer>,
) -> Result<EncodedLayer, crate::codec::Error> {
    let mut diagnostics = Vec::new();
    let (next, materialized_next) =
        resolve_next_header(name, next_header, context, &mut diagnostics)?;
    let unpadded = options
        .len()
        .checked_add(2)
        .ok_or_else(|| invalid(name, "option length overflow"))?;
    let header_len = unpadded
        .checked_next_multiple_of(8)
        .ok_or_else(|| invalid(name, "option padding overflow"))?;
    let hdr_ext_len = u8::try_from((header_len / 8).saturating_sub(1))
        .map_err(|_| invalid(name, "options header exceeds 2048-byte secure default"))?;
    let mut prefix = Vec::with_capacity(header_len);
    prefix.push(next);
    prefix.push(hdr_ext_len);
    prefix.extend_from_slice(options);
    prefix.resize(header_len, 0);
    let padded_options = Bytes::copy_from_slice(&prefix[2..header_len]);
    let materialized = materialize(materialized_next, padded_options);
    Ok(EncodedLayer::header(prefix, materialized)
        .with_fields(layout(header_len))
        .with_diagnostics(diagnostics))
}

fn decode_options<L>(
    name: &'static str,
    input: Bytes,
    make: impl FnOnce(u8, Bytes) -> L,
    layout: fn(usize) -> Vec<crate::layout::FieldLayout>,
) -> Result<DecodedLayer, crate::codec::Error>
where
    L: Layer + 'static,
{
    let Some(header) = input.first_chunk::<8>() else {
        return Err(truncated(name, 8, input.len()));
    };
    let header_len = usize::from(header[1])
        .saturating_add(1)
        .checked_mul(8)
        .ok_or_else(|| invalid(name, "header length overflow"))?;
    if input.len() < header_len {
        return Err(truncated(name, header_len, input.len()));
    }
    let options = input
        .get(2..header_len)
        .ok_or_else(|| truncated(name, header_len, input.len()))?;
    Ok(DecodedLayer {
        layer: Box::new(make(header[0], input.slice_ref(options))),
        consumed: header_len,
        payload_len: input.len().saturating_sub(header_len),
        next: vec![Discriminator(u64::from(header[0]))],
        fields: layout(header_len),
        diagnostics: Vec::new(),
        stop: input.len() == header_len,
        network: None,
    })
}

impl LayerCodec for HopByHopCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &hop_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<HopByHop>(HOP_NAME, layer)?;
        encode_options(
            HOP_NAME,
            &layer.next_header,
            &layer.options,
            hop_layout,
            context,
            |next_header, options| {
                Box::new(HopByHop {
                    next_header,
                    options,
                })
            },
        )
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        decode_options(
            HOP_NAME,
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(HopByHop::default(), fields)
    }
}

impl LayerCodec for DestinationOptionsCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &destination_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<DestinationOptions>(DESTINATION_NAME, layer)?;
        encode_options(
            DESTINATION_NAME,
            &layer.next_header,
            &layer.options,
            destination_layout,
            context,
            |next_header, options| {
                Box::new(DestinationOptions {
                    next_header,
                    options,
                })
            },
        )
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        decode_options(
            DESTINATION_NAME,
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(DestinationOptions::default(), fields)
    }
}
