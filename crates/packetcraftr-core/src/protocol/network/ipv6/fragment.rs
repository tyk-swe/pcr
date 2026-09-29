// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    child_is_opaque, expected_discriminator, invalid, make_layer, payload_without_padding,
    protocol, resolve_u8, strict_or_diagnostic, truncated, typed_layer,
    validate_auto_raw_discriminator, validate_ipv6_routing_child, validate_raw_child_discriminator,
};

use crate::protocol::{BuiltinProtocol, network::ip_protocol};

const NAME: &str = BuiltinProtocol::Ipv6Fragment.as_str();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub next_header: WireValue<u8>,
    /// Reserved byte after the next header; receivers ignore it.
    pub reserved: u8,
    /// Offset in eight-byte units, as encoded on the wire.
    pub fragment_offset: u16,
    /// The two reserved bits before the more-fragments flag; receivers ignore them.
    pub reserved_bits: u8,
    pub more_fragments: bool,
    pub identification: u32,
}

impl Default for Fragment {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            reserved: 0,
            fragment_offset: 0,
            reserved_bits: 0,
            more_fragments: false,
            identification: 0,
        }
    }
}

reflective_layer! {
    fn fragment_schema() => { protocol: protocol(NAME), name: "IPv6 Fragment" }
    impl Fragment {
        "next_header" => { kind: Unsigned, derived: true, required: false, description: "IPv6 next-header discriminator", reflect: next_header, layout: (0, 1) },
        "reserved" => { kind: Unsigned, derived: false, required: false, description: "Reserved byte after the next header", reflect: reserved, layout: (1, 2) },
        "fragment_offset" => { kind: Unsigned, derived: false, required: true, description: "Fragment offset in eight-byte units", reflect_bounded: fragment_offset, 0x1fff_u64, layout: (2, 4) },
        "reserved_bits" => { kind: Unsigned, derived: false, required: false, description: "Two reserved bits before the more-fragments flag", reflect_bounded: reserved_bits, 3_u64, layout: (2, 4) },
        "more_fragments" => { kind: Bool, derived: false, required: true, description: "More-fragments flag", reflect: more_fragments, layout: (2, 4) },
        "identification" => { kind: Unsigned, derived: false, required: true, description: "Fragment identification", reflect: identification, layout: (4, 8) },
    }
    layout pub(crate) fn fragment_layout();
}

fn nonzero_reserved_fields(reserved: u8, reserved_bits: u8) -> impl Iterator<Item = &'static str> {
    [("reserved", reserved), ("reserved_bits", reserved_bits)]
        .into_iter()
        .filter(|(_, value)| *value != 0)
        .map(|(field, _)| field)
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FragmentCodec;

impl LayerCodec for FragmentCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &fragment_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Fragment>(NAME, layer)?;
        if layer.fragment_offset > 0x1fff {
            return Err(invalid(NAME, "fragment offset exceeds 13 bits"));
        }
        if layer.reserved_bits > 3 {
            return Err(invalid(NAME, "reserved bits exceed two bits"));
        }
        let expectation = expected_discriminator(
            NAME,
            context,
            ip_protocol::NO_NEXT_HEADER,
            &layer.next_header,
        );
        let mut diagnostics = Vec::new();
        validate_auto_raw_discriminator(
            NAME,
            "next_header",
            &layer.next_header,
            context,
            &mut diagnostics,
        )?;
        for field in nonzero_reserved_fields(layer.reserved, layer.reserved_bits) {
            strict_or_diagnostic(
                NAME,
                "build.ipv6_fragment_reserved",
                field,
                "IPv6 Fragment reserved fields must be zero on transmission",
                context,
                &mut diagnostics,
            )?;
        }
        let covered_payload = payload_without_padding(NAME, payload, context)?;
        if layer.more_fragments && covered_payload.len() % 8 != 0 {
            strict_or_diagnostic(
                NAME,
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
            && context.child.is_some_and(|child| !child_is_opaque(child))
        {
            strict_or_diagnostic(
                NAME,
                "build.typed_fragment_payload",
                "fragment_offset",
                "fragment payload must be Raw; convert typed fragment payloads to Raw explicitly",
                context,
                &mut diagnostics,
            )?;
        }
        let (next, materialized_next) = resolve_u8(
            NAME,
            "next_header",
            &layer.next_header,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        if layer.fragment_offset == 0 && !layer.more_fragments {
            validate_raw_child_discriminator(NAME, u64::from(next), context, &mut diagnostics)?;
        }
        validate_ipv6_routing_child(NAME, next, context, &mut diagnostics)?;
        let offset_flags = (layer.fragment_offset << 3)
            | (u16::from(layer.reserved_bits) << 1)
            | u16::from(layer.more_fragments);
        let mut prefix = Vec::with_capacity(8);
        prefix.extend_from_slice(&[next, layer.reserved]);
        prefix.extend_from_slice(&offset_flags.to_be_bytes());
        prefix.extend_from_slice(&layer.identification.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.next_header = materialized_next;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(fragment_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<8>() else {
            return Err(truncated(NAME, 8, input.len()));
        };
        let offset_flags = u16::from_be_bytes([header[2], header[3]]);
        let fragment_offset = offset_flags >> 3;
        let reserved_bits = (header[3] >> 1) & 3;
        let diagnostics = nonzero_reserved_fields(header[1], reserved_bits)
            .map(|field| {
                Diagnostic::warning(
                    "decode.ipv6_fragment_reserved",
                    "IPv6 Fragment reserved bits are non-zero",
                )
                .at_field(field)
            })
            .collect();
        Ok(DecodedLayer {
            layer: Box::new(Fragment {
                next_header: WireValue::Exact(header[0]),
                reserved: header[1],
                fragment_offset,
                reserved_bits,
                more_fragments: offset_flags & 1 != 0,
                identification: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            }),
            consumed: 8,
            payload_len: input.len().saturating_sub(8),
            next: if fragment_offset == 0 && offset_flags & 1 == 0 {
                vec![Discriminator(u64::from(header[0]))]
            } else {
                vec![Discriminator(255)]
            },
            fields: fragment_layout(),
            diagnostics,
            stop: input.len() == 8,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Fragment::default(), fields)
    }
}
