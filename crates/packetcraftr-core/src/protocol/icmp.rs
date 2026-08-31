// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Internet Control Message Protocol models.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, ICMPV4_CHECKSUM, ICMPV6_CHECKSUM},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
};

use super::common::{
    ValueExpectation, checksum, checksum_parts, ensure_encode_budget, invalid, make_layer,
    payload_without_padding, protocol, resolve_u16, transport_checksum, transport_checksum_parts,
    truncated, typed_layer,
};
use super::network::resolve_envelope;

use crate::protocol::BuiltinProtocol;

const V4_NAME: &str = BuiltinProtocol::Icmpv4.as_str();
const V6_NAME: &str = BuiltinProtocol::Icmpv6.as_str();

const ICMP_MIN_LEN: usize = 4;

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
    ($ty:ty, $schema:ident, $protocol:expr, $name:literal, $layout:ident) => {
        reflective_layer! {
            fn $schema() => { protocol: protocol($protocol), name: $name }
            impl $ty {
                "type" => {
                    kind: Unsigned, derived: false, required: true,
                    description: "ICMP message type",
                    reflect: icmp_type,
                    layout: (0, 1)
                },
                "code" => {
                    kind: Unsigned, derived: false, required: true,
                    description: "ICMP message code",
                    reflect: code,
                    layout: (1, 2)
                },
                "checksum" => {
                    kind: Unsigned, derived: true, required: false,
                    description: "ICMP checksum",
                    reflect: checksum,
                    layout: (2, 4)
                },
                "body" => {
                    kind: Bytes, derived: false, required: false,
                    description: "Type-specific ICMP body",
                    reflect: body,
                    layout: (4, 4_usize.saturating_add(body_len))
                },
            }
            layout pub(crate) fn $layout(body_len: usize);
        }
    };
}

icmp_reflection!(Icmpv4, icmpv4_schema, V4_NAME, "ICMPv4", icmpv4_layout);
icmp_reflection!(Icmpv6, icmpv6_schema, V6_NAME, "ICMPv6", icmpv6_layout);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Icmpv4Codec;

impl LayerCodec for Icmpv4Codec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &icmpv4_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Icmpv4>(V4_NAME, layer)?;
        let contribution = ICMP_MIN_LEN
            .checked_add(layer.body.len())
            .ok_or_else(|| invalid(V4_NAME, "message length overflow"))?;
        ensure_encode_budget(V4_NAME, contribution, context)?;
        let covered_payload = payload_without_padding(V4_NAME, payload, context)?;
        let mut prefix = Vec::with_capacity(contribution);
        prefix.extend_from_slice(&[layer.icmp_type, layer.code, 0, 0]);
        prefix.extend_from_slice(&layer.body);
        let expected = checksum_parts(&[&prefix, covered_payload]);
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            V4_NAME,
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "prefix begins with the four-byte ICMP header pushed above"
        )]
        {
            prefix[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(icmpv4_layout(layer.body.len()))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(header) = input.first_chunk::<ICMP_MIN_LEN>() else {
            return Err(truncated(V4_NAME, ICMP_MIN_LEN, input.len()));
        };
        let body = input.get(ICMP_MIN_LEN..).unwrap_or_default();
        let mut diagnostics = Vec::new();
        if checksum(input) != 0 {
            diagnostics.push(
                Diagnostic::warning(ICMPV4_CHECKSUM, "ICMPv4 checksum mismatch")
                    .at_field("checksum"),
            );
        }
        Ok(DecodedLayerValue {
            layer: Box::new(Icmpv4 {
                icmp_type: header[0],
                code: header[1],
                checksum: WireValue::Exact(u16::from_be_bytes([header[2], header[3]])),
                body: Bytes::copy_from_slice(body),
            }),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: icmpv4_layout(body.len()),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Icmpv4::default(), fields)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Icmpv6Codec;

impl LayerCodec for Icmpv6Codec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &icmpv6_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Icmpv6>(V6_NAME, layer)?;
        let contribution = ICMP_MIN_LEN
            .checked_add(layer.body.len())
            .ok_or_else(|| invalid(V6_NAME, "message length overflow"))?;
        ensure_encode_budget(V6_NAME, contribution, context)?;
        let covered_payload = payload_without_padding(V6_NAME, payload, context)?;
        let mut prefix = Vec::with_capacity(contribution);
        prefix.extend_from_slice(&[layer.icmp_type, layer.code, 0, 0]);
        prefix.extend_from_slice(&layer.body);
        let expected = transport_checksum_parts(
            V6_NAME,
            resolve_envelope(V6_NAME, context)?,
            58,
            &[&prefix, covered_payload],
        )?;
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            V6_NAME,
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "prefix begins with the four-byte ICMP header pushed above"
        )]
        {
            prefix[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(icmpv6_layout(layer.body.len()))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(header) = input.first_chunk::<ICMP_MIN_LEN>() else {
            return Err(truncated(V6_NAME, ICMP_MIN_LEN, input.len()));
        };
        let body = input.get(ICMP_MIN_LEN..).unwrap_or_default();
        let mut diagnostics = Vec::new();
        if let Some(network) = context.network
            && transport_checksum(V6_NAME, network, 58, input)? != 0
        {
            diagnostics.push(
                Diagnostic::warning(ICMPV6_CHECKSUM, "ICMPv6 checksum mismatch")
                    .at_field("checksum"),
            );
        }
        Ok(DecodedLayerValue {
            layer: Box::new(Icmpv6 {
                icmp_type: header[0],
                code: header[1],
                checksum: WireValue::Exact(u16::from_be_bytes([header[2], header[3]])),
                body: Bytes::copy_from_slice(body),
            }),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: icmpv6_layout(body.len()),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Icmpv6::default(), fields)
    }
}
