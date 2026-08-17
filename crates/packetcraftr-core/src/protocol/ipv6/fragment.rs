// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::{
    codec::{
        DecodedLayerValue, EncodedLayer, Error as CodecError, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Id as ProtocolId, Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    expected_discriminator, invalid, make_layer, payload_without_padding, protocol, resolve_u8,
    strict_or_diagnostic, truncated, validate_auto_raw_discriminator, validate_ipv6_routing_child,
    validate_raw_child_discriminator, wrong_layer,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub next_header: WireValue<u8>,
    /// Offset in eight-byte units, as encoded on the wire.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub identification: u32,
}

impl Default for Fragment {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            fragment_offset: 0,
            more_fragments: false,
            identification: 0,
        }
    }
}

reflective_layer! {
    fn fragment_schema() => { protocol: protocol("ipv6_fragment"), name: "IPv6 Fragment" }
    impl Fragment {
        "next_header" => { kind: Unsigned, derived: true, required: false, description: "IPv6 next-header discriminator", reflect: next_header, layout: (0, 1) },
        "fragment_offset" => { kind: Unsigned, derived: false, required: true, description: "Fragment offset in eight-byte units", reflect_bounded: fragment_offset, 0x1fff_u64, layout: (2, 4) },
        "more_fragments" => { kind: Bool, derived: false, required: true, description: "More-fragments flag", reflect: more_fragments, layout: (2, 4) },
        "identification" => { kind: Unsigned, derived: false, required: true, description: "Fragment identification", reflect: identification, layout: (4, 8) },
    }
    layout pub(crate) fn fragment_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ipv6FragmentCodec;

impl LayerCodec for Ipv6FragmentCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6_fragment")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Fragment>()
            .ok_or_else(|| wrong_layer("ipv6_fragment", layer))?;
        if layer.fragment_offset > 0x1fff {
            return Err(invalid("ipv6_fragment", "fragment offset exceeds 13 bits"));
        }
        let expectation = expected_discriminator("ipv6_fragment", context, 59_u8);
        let mut diagnostics = Vec::new();
        validate_auto_raw_discriminator(
            "ipv6_fragment",
            "next_header",
            &layer.next_header,
            context,
            &mut diagnostics,
        )?;
        let covered_payload = payload_without_padding("ipv6_fragment", payload, context)?;
        if layer.more_fragments && covered_payload.len() % 8 != 0 {
            strict_or_diagnostic(
                "ipv6_fragment",
                "build.ipv6_fragment_alignment",
                "more_fragments",
                format!(
                    "non-final fragment payload length {} is not a multiple of eight bytes",
                    covered_payload.len()
                ),
                context,
                &mut diagnostics,
            )?;
        }
        if (layer.fragment_offset != 0 || layer.more_fragments)
            && context.child.is_some_and(|child| {
                !matches!(
                    child.protocol_id().as_str(),
                    "raw" | "padding" | "malformed"
                )
            })
        {
            strict_or_diagnostic(
                "ipv6_fragment",
                "build.typed_fragment_payload",
                "fragment_offset",
                "fragment payload must be Raw; convert typed fragment payloads to Raw explicitly",
                context,
                &mut diagnostics,
            )?;
        }
        let (next, materialized_next) = resolve_u8(
            "ipv6_fragment",
            "next_header",
            &layer.next_header,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        if layer.fragment_offset == 0 && !layer.more_fragments {
            validate_raw_child_discriminator(
                "ipv6_fragment",
                u64::from(next),
                context,
                &mut diagnostics,
            )?;
        }
        validate_ipv6_routing_child("ipv6_fragment", next, context, &mut diagnostics)?;
        let offset_flags = (layer.fragment_offset << 3) | u16::from(layer.more_fragments);
        let mut prefix = Vec::with_capacity(8);
        prefix.extend_from_slice(&[next, 0]);
        prefix.extend_from_slice(&offset_flags.to_be_bytes());
        prefix.extend_from_slice(&layer.identification.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.next_header = materialized_next;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: fragment_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 8 {
            return Err(truncated("ipv6_fragment", 8, input.len()));
        }
        let offset_flags = u16::from_be_bytes([input[2], input[3]]);
        if input[1] != 0 || offset_flags & 0x0006 != 0 {
            return Err(invalid("ipv6_fragment", "reserved bits are non-zero"));
        }
        let fragment_offset = offset_flags >> 3;
        Ok(DecodedLayerValue {
            layer: Box::new(Fragment {
                next_header: WireValue::Exact(input[0]),
                fragment_offset,
                more_fragments: offset_flags & 1 != 0,
                identification: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
            }),
            consumed: 8,
            payload_len: input.len() - 8,
            next: if fragment_offset == 0 && offset_flags & 1 == 0 {
                vec![Discriminator(u64::from(input[0]))]
            } else {
                // Non-atomic fragments retain opaque Raw payloads.
                vec![Discriminator(255)]
            },
            fields: fragment_layout(),
            diagnostics: Vec::new(),
            stop: input.len() == 8,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Fragment::default(), fields)
    }
}
