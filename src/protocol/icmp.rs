// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::OnceLock;

use bytes::Bytes;

use crate::packet::internal::{
    CodecError, DecodedLayerValue, Diagnostic, EncodedLayer, FieldError, FieldKind, FieldSchema,
    FieldValue, Layer, LayerCodec, LayerDecodeContext, LayerEncodeContext, LayerSchema, ProtocolId,
    WireValue,
};

use super::common::{
    ValueExpectation, bytes, checksum, ensure_encode_budget, field_layout, impl_layer_boilerplate,
    invalid, make_layer, out_of_range, payload_without_padding, protocol, resolve_u16,
    set_wire_u16, transport_checksum, truncated, unknown_field, wire_u16, wrong_layer, wrong_type,
};
use super::ip::encode_network;

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

fn icmp_fields() -> &'static [FieldSchema] {
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "type",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "ICMP message type",
        },
        FieldSchema {
            name: "code",
            kind: FieldKind::Unsigned,
            derived: false,
            required: true,
            description: "ICMP message code",
        },
        FieldSchema {
            name: "checksum",
            kind: FieldKind::Unsigned,
            derived: true,
            required: false,
            description: "ICMP checksum",
        },
        FieldSchema {
            name: "body",
            kind: FieldKind::Bytes,
            derived: false,
            required: false,
            description: "Type-specific ICMP body",
        },
    ];
    FIELDS
}

fn icmpv4_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("icmpv4"),
        name: "ICMPv4",
        fields: icmp_fields(),
    })
}

fn icmpv6_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: protocol("icmpv6"),
        name: "ICMPv6",
        fields: icmp_fields(),
    })
}

macro_rules! impl_icmp_layer {
    ($ty:ty, $schema:path) => {
        impl Layer for $ty {
            impl_layer_boilerplate!($ty, $schema);

            fn field(&self, name: &str) -> Option<FieldValue> {
                match name {
                    "type" => Some(self.icmp_type.into()),
                    "code" => Some(self.code.into()),
                    "checksum" => Some(wire_u16(&self.checksum)),
                    "body" => Some(self.body.clone().into()),
                    _ => None,
                }
            }

            fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
                match (name, value) {
                    ("type", FieldValue::Unsigned(value)) => {
                        self.icmp_type =
                            u8::try_from(value).map_err(|_| out_of_range($schema(), name))?
                    }
                    ("code", FieldValue::Unsigned(value)) => {
                        self.code =
                            u8::try_from(value).map_err(|_| out_of_range($schema(), name))?
                    }
                    ("checksum", value) => {
                        return set_wire_u16(&mut self.checksum, $schema(), name, value);
                    }
                    ("body", value) => {
                        self.body =
                            bytes(&value).ok_or_else(|| wrong_type($schema(), name, "bytes"))?
                    }
                    ("type" | "code", _) => return Err(wrong_type($schema(), name, "unsigned")),
                    _ => return Err(unknown_field($schema(), name)),
                }
                Ok(())
            }

            fn normalize(&mut self) {
                self.checksum.normalize();
            }
        }
    };
}

impl_icmp_layer!(Icmpv4, icmpv4_schema);
impl_icmp_layer!(Icmpv6, icmpv6_schema);

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Icmpv4Codec;

impl LayerCodec for Icmpv4Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("icmpv4")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::support::aliases(self.protocol_id().as_str())
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
        let capacity = contribution
            .checked_add(payload.len())
            .ok_or_else(|| invalid("icmpv4", "message length overflow"))?;
        let mut message = Vec::with_capacity(capacity);
        message.extend_from_slice(&[layer.icmp_type, layer.code, 0, 0]);
        message.extend_from_slice(&layer.body);
        message.extend_from_slice(payload_without_padding("icmpv4", payload, context)?);
        let expected = checksum(&message);
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            "icmpv4",
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        let mut prefix = message[..ICMP_MIN_LEN + layer.body.len()].to_vec();
        prefix[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: icmp_layout(layer.body.len()),
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
            fields: icmp_layout(input.len() - ICMP_MIN_LEN),
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
pub(super) struct Icmpv6Codec;

impl LayerCodec for Icmpv6Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("icmpv6")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::support::aliases(self.protocol_id().as_str())
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
        let capacity = contribution
            .checked_add(payload.len())
            .ok_or_else(|| invalid("icmpv6", "message length overflow"))?;
        let mut message = Vec::with_capacity(capacity);
        message.extend_from_slice(&[layer.icmp_type, layer.code, 0, 0]);
        message.extend_from_slice(&layer.body);
        message.extend_from_slice(payload_without_padding("icmpv6", payload, context)?);
        let expected = transport_checksum(encode_network(context)?, 58, &message)?;
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            "icmpv6",
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        let mut prefix = message[..ICMP_MIN_LEN + layer.body.len()].to_vec();
        prefix[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: icmp_layout(layer.body.len()),
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
            fields: icmp_layout(input.len() - ICMP_MIN_LEN),
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

fn icmp_layout(body_len: usize) -> Vec<crate::packet::internal::FieldLayout> {
    vec![
        field_layout("type", 0, 1),
        field_layout("code", 1, 2),
        field_layout("checksum", 2, 4),
        field_layout("body", 4, 4 + body_len),
    ]
}
