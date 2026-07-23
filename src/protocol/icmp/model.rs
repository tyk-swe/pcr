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
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
};

use super::super::common::{
    ValueExpectation, checksum, checksum_parts, ensure_encode_budget, invalid, make_layer,
    payload_without_padding, protocol, resolve_u16, transport_checksum, transport_checksum_parts,
    truncated, wrong_layer,
};
use super::super::network::encode_network;

const ICMP_MIN_LEN: usize = 4;

fn ensure_message_length(
    name: &str,
    contribution: usize,
    payload_len: usize,
) -> Result<(), CodecError> {
    // Validate the full input before trailing padding is excluded from the checksum.
    contribution
        .checked_add(payload_len)
        .ok_or_else(|| invalid(name, "message length overflow"))?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv4 {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: WireValue<u16>,
    pub body: Bytes,
}

impl Default for Icmpv4 {
    fn default() -> Self {
        Self {
            icmp_type: 8,
            code: 0,
            checksum: WireValue::Auto,
            body: Bytes::from_static(&[0, 0, 0, 0]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv6 {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: WireValue<u16>,
    pub body: Bytes,
}

impl Default for Icmpv6 {
    fn default() -> Self {
        Self {
            icmp_type: 128,
            code: 0,
            checksum: WireValue::Auto,
            body: Bytes::from_static(&[0, 0, 0, 0]),
        }
    }
}

macro_rules! icmp_reflection {
    ($ty:ty, $schema:ident, $protocol:literal, $name:literal, $layout:ident) => {
        reflective_layer! {
            fn $schema() => { protocol: protocol($protocol), name: $name }
            impl $ty {
                "type" => {
                    kind: Unsigned, derived: false, required: true,
                    description: "ICMP message type",
                    get |layer| Some(reflect_get(&layer.icmp_type)),
                    set |layer, value, name| reflect_set(&mut layer.icmp_type, $schema(), name, value),
                    layout: (0, 1)
                },
                "code" => {
                    kind: Unsigned, derived: false, required: true,
                    description: "ICMP message code",
                    get |layer| Some(reflect_get(&layer.code)),
                    set |layer, value, name| reflect_set(&mut layer.code, $schema(), name, value),
                    layout: (1, 2)
                },
                "checksum" => {
                    kind: Unsigned, derived: true, required: false,
                    description: "ICMP checksum",
                    get |layer| Some(reflect_get(&layer.checksum)),
                    set |layer, value, name| reflect_set(&mut layer.checksum, $schema(), name, value),
                    layout: (2, 4)
                },
                "body" => {
                    kind: Bytes, derived: false, required: false,
                    description: "Type-specific ICMP body",
                    get |layer| Some(reflect_get(&layer.body)),
                    set |layer, value, name| reflect_set(&mut layer.body, $schema(), name, value),
                    layout: (4, 4 + body_len)
                },
                normalize |layer| { layer.checksum.normalize(); }
            }
            layout fn $layout(body_len: usize);
        }
    };
}

icmp_reflection!(Icmpv4, icmpv4_schema, "icmpv4", "ICMPv4", icmpv4_layout);
icmp_reflection!(Icmpv6, icmpv6_schema, "icmpv6", "ICMPv6", icmpv6_layout);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Icmpv4Codec;

impl LayerCodec for Icmpv4Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("icmpv4")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Icmpv4>()
            .ok_or_else(|| wrong_layer("icmpv4", layer))?;
        let contribution = ICMP_MIN_LEN
            .checked_add(layer.body.len())
            .ok_or_else(|| invalid("icmpv4", "message length overflow"))?;
        ensure_encode_budget("icmpv4", contribution, context)?;
        ensure_message_length("icmpv4", contribution, payload.len())?;
        let covered_payload = payload_without_padding("icmpv4", payload, context)?;
        let mut prefix = Vec::with_capacity(contribution);
        prefix.extend_from_slice(&[layer.icmp_type, layer.code, 0, 0]);
        prefix.extend_from_slice(&layer.body);
        let expected = checksum_parts(&[&prefix, covered_payload]);
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            "icmpv4",
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        prefix[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: icmpv4_layout(layer.body.len()),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < ICMP_MIN_LEN {
            return Err(truncated("icmpv4", ICMP_MIN_LEN, input.len()));
        }
        let mut diagnostics = Vec::new();
        if context.verify_checksums && checksum(input) != 0 {
            diagnostics.push(
                Diagnostic::warning("decode.icmpv4_checksum", "ICMPv4 checksum mismatch")
                    .at_field("checksum"),
            );
        }
        Ok(DecodedLayerValue {
            layer: Box::new(Icmpv4 {
                icmp_type: input[0],
                code: input[1],
                checksum: WireValue::Exact(u16::from_be_bytes([input[2], input[3]])),
                body: Bytes::copy_from_slice(&input[4..]),
            }),
            consumed: input.len(),
            payload_offset: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: icmpv4_layout(input.len() - ICMP_MIN_LEN),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Icmpv4::default(), fields)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Icmpv6Codec;

impl LayerCodec for Icmpv6Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("icmpv6")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Icmpv6>()
            .ok_or_else(|| wrong_layer("icmpv6", layer))?;
        let contribution = ICMP_MIN_LEN
            .checked_add(layer.body.len())
            .ok_or_else(|| invalid("icmpv6", "message length overflow"))?;
        ensure_encode_budget("icmpv6", contribution, context)?;
        ensure_message_length("icmpv6", contribution, payload.len())?;
        let covered_payload = payload_without_padding("icmpv6", payload, context)?;
        let mut prefix = Vec::with_capacity(contribution);
        prefix.extend_from_slice(&[layer.icmp_type, layer.code, 0, 0]);
        prefix.extend_from_slice(&layer.body);
        let expected =
            transport_checksum_parts(encode_network(context)?, 58, &[&prefix, covered_payload])?;
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            "icmpv6",
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        prefix[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: icmpv6_layout(layer.body.len()),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < ICMP_MIN_LEN {
            return Err(truncated("icmpv6", ICMP_MIN_LEN, input.len()));
        }
        let mut diagnostics = Vec::new();
        if context.verify_checksums
            && let Some(network) = context.network
            && transport_checksum(network, 58, input)? != 0
        {
            diagnostics.push(
                Diagnostic::warning("decode.icmpv6_checksum", "ICMPv6 checksum mismatch")
                    .at_field("checksum"),
            );
        }
        Ok(DecodedLayerValue {
            layer: Box::new(Icmpv6 {
                icmp_type: input[0],
                code: input[1],
                checksum: WireValue::Exact(u16::from_be_bytes([input[2], input[3]])),
                body: Bytes::copy_from_slice(&input[4..]),
            }),
            consumed: input.len(),
            payload_offset: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: icmpv6_layout(input.len() - ICMP_MIN_LEN),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Icmpv6::default(), fields)
    }
}
