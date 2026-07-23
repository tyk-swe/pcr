// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, checksum, checksum_parts, ensure_encode_budget, expected_discriminator,
    invalid, make_layer, out_of_range, payload_without_padding, protocol, resolve_u16,
    strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_raw_child_discriminator, wrong_layer, wrong_type,
};

const GRE_BASE_LEN: usize = 4;
const GRE_OPTION_LEN: usize = 4;
const CHECKSUM_PRESENT: u16 = 0x8000;
const ROUTING_PRESENT: u16 = 0x4000;
const KEY_PRESENT: u16 = 0x2000;
const SEQUENCE_PRESENT: u16 = 0x1000;
const MUST_DISCARD_FLAGS: u16 = 0x0c00;
const IGNORED_RESERVED_FLAGS: u16 = 0x03f8;
const VERSION_MASK: u16 = 0x0007;

fn gre_header_len(checksum: bool, key: bool, sequence: bool) -> usize {
    GRE_BASE_LEN
        + usize::from(checksum) * GRE_OPTION_LEN
        + usize::from(key) * GRE_OPTION_LEN
        + usize::from(sequence) * GRE_OPTION_LEN
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gre {
    pub protocol_type: WireValue<u16>,
    pub checksum: Option<WireValue<u16>>,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
    pub reserved_bits: u8,
}

impl Default for Gre {
    fn default() -> Self {
        Self {
            protocol_type: WireValue::Auto,
            checksum: None,
            key: None,
            sequence: None,
            reserved_bits: 0,
        }
    }
}

reflective_layer! {
    fn gre_schema() => { protocol: protocol("gre"), name: "GRE" }
    impl Gre {
        "protocol_type" => { kind: Unsigned, derived: true, required: false, description: "Encapsulated EtherType discriminator", get |layer| Some(reflect_get(&layer.protocol_type)), set |layer, value, name| reflect_set(&mut layer.protocol_type, gre_schema(), name, value), layout: (2, 4) },
        "checksum" => { kind: Unsigned, derived: true, required: false, description: "Optional checksum over the GRE header and payload", get |layer| layer.checksum.as_ref().map(reflect_get), set |layer, value, name| { let mut checksum = layer.checksum.clone().unwrap_or_default(); reflect_set(&mut checksum, gre_schema(), name, value)?; layer.checksum = Some(checksum); Ok(()) } },
        "key" => { kind: Unsigned, derived: false, required: false, description: "Optional GRE key", get |layer| layer.key.map(FieldValue::from), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.key = Some(u32::try_from(value).map_err(|_| out_of_range(gre_schema(), name))?); Ok(()) }, _ => Err(wrong_type(gre_schema(), name, "unsigned")) } },
        "sequence" => { kind: Unsigned, derived: false, required: false, description: "Optional GRE sequence number", get |layer| layer.sequence.map(FieldValue::from), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.sequence = Some(u32::try_from(value).map_err(|_| out_of_range(gre_schema(), name))?); Ok(()) }, _ => Err(wrong_type(gre_schema(), name, "unsigned")) } },
        "reserved_bits" => { kind: Unsigned, derived: false, required: false, description: "Receiver-ignored GRE bits 6 through 12", get |layer| Some(reflect_get(&layer.reserved_bits)), set |layer, value, name| reflect_set(&mut layer.reserved_bits, gre_schema(), name, value), layout: (0, 2) },
        normalize |layer| { layer.protocol_type.normalize(); if let Some(checksum) = &mut layer.checksum { checksum.normalize(); } }
    }
    layout fn gre_static_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GreCodec;

impl LayerCodec for GreCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("gre")
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
            .downcast_ref::<Gre>()
            .ok_or_else(|| wrong_layer("gre", layer))?;
        let header_len = gre_header_len(
            layer.checksum.is_some(),
            layer.key.is_some(),
            layer.sequence.is_some(),
        );
        ensure_encode_budget("gre", header_len, context)?;
        let covered_payload = payload_without_padding("gre", payload, context)?;

        let mut diagnostics = Vec::new();
        if layer.reserved_bits > 0x7f {
            return Err(invalid("gre", "reserved bits exceed the 7-bit wire field"));
        }
        if layer.reserved_bits != 0 {
            strict_or_diagnostic(
                "gre",
                "build.gre_reserved_bits",
                "reserved_bits",
                "GRE bits 6 through 12 must be zero on transmission",
                context,
                &mut diagnostics,
            )?;
        }
        validate_auto_raw_discriminator(
            "gre",
            "protocol_type",
            &layer.protocol_type,
            context,
            &mut diagnostics,
        )?;
        let (protocol_type, materialized_protocol_type) = resolve_u16(
            "gre",
            "protocol_type",
            &layer.protocol_type,
            expected_discriminator("gre", context, 0_u16),
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "gre",
            u64::from(protocol_type),
            context,
            &mut diagnostics,
        )?;

        let flags = if layer.checksum.is_some() {
            CHECKSUM_PRESENT
        } else {
            0
        } | if layer.key.is_some() { KEY_PRESENT } else { 0 }
            | if layer.sequence.is_some() {
                SEQUENCE_PRESENT
            } else {
                0
            }
            | (u16::from(layer.reserved_bits) << 3);
        let mut prefix = Vec::with_capacity(header_len);
        prefix.extend_from_slice(&flags.to_be_bytes());
        prefix.extend_from_slice(&protocol_type.to_be_bytes());
        if layer.checksum.is_some() {
            prefix.extend_from_slice(&[0; GRE_OPTION_LEN]);
        }
        if let Some(key) = layer.key {
            prefix.extend_from_slice(&key.to_be_bytes());
        }
        if let Some(sequence) = layer.sequence {
            prefix.extend_from_slice(&sequence.to_be_bytes());
        }

        let materialized_checksum = if let Some(checksum_value) = &layer.checksum {
            let expected = checksum_parts(&[&prefix, covered_payload]);
            let (checksum, materialized) = resolve_u16(
                "gre",
                "checksum",
                checksum_value,
                ValueExpectation::Required(expected),
                context.mode,
                &mut diagnostics,
            )?;
            prefix[4..6].copy_from_slice(&checksum.to_be_bytes());
            Some(materialized)
        } else {
            None
        };

        let mut materialized = layer.clone();
        materialized.protocol_type = materialized_protocol_type;
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: gre_layout(layer),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < GRE_BASE_LEN {
            return Err(truncated("gre", GRE_BASE_LEN, input.len()));
        }
        let flags = u16::from_be_bytes([input[0], input[1]]);
        let version = flags & VERSION_MASK;
        if version != 0 {
            return Err(CodecError::Unsupported {
                protocol: protocol("gre"),
                message: format!("GRE version {version} is not supported"),
            });
        }
        if flags & ROUTING_PRESENT != 0 {
            return Err(CodecError::Unsupported {
                protocol: protocol("gre"),
                message: "GRE routing fields are not supported".to_owned(),
            });
        }
        if flags & MUST_DISCARD_FLAGS != 0 {
            return Err(CodecError::Unsupported {
                protocol: protocol("gre"),
                message: format!(
                    "must-discard GRE flags are non-zero (0x{:04x})",
                    flags & MUST_DISCARD_FLAGS
                ),
            });
        }

        let checksum_present = flags & CHECKSUM_PRESENT != 0;
        let key_present = flags & KEY_PRESENT != 0;
        let sequence_present = flags & SEQUENCE_PRESENT != 0;
        let header_len = gre_header_len(checksum_present, key_present, sequence_present);
        if input.len() < header_len {
            return Err(truncated("gre", header_len, input.len()));
        }

        let protocol_type = u16::from_be_bytes([input[2], input[3]]);
        let mut cursor = GRE_BASE_LEN;
        let checksum_value = if checksum_present {
            let value = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
            if input[cursor + 2] != 0 || input[cursor + 3] != 0 {
                return Err(invalid("gre", "reserved1 field is non-zero"));
            }
            cursor += GRE_OPTION_LEN;
            Some(WireValue::Exact(value))
        } else {
            None
        };
        let key = if key_present {
            let value = u32::from_be_bytes([
                input[cursor],
                input[cursor + 1],
                input[cursor + 2],
                input[cursor + 3],
            ]);
            cursor += GRE_OPTION_LEN;
            Some(value)
        } else {
            None
        };
        let sequence = if sequence_present {
            Some(u32::from_be_bytes([
                input[cursor],
                input[cursor + 1],
                input[cursor + 2],
                input[cursor + 3],
            ]))
        } else {
            None
        };

        let mut diagnostics = Vec::new();
        let reserved_bits = ((flags & IGNORED_RESERVED_FLAGS) >> 3) as u8;
        if reserved_bits != 0 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.gre_reserved_bits",
                    "receiver-ignored GRE bits 6 through 12 are non-zero",
                )
                .at_field("reserved_bits"),
            );
        }
        if checksum_present && context.verify_checksums && checksum(input) != 0 {
            diagnostics.push(
                Diagnostic::warning("decode.gre_checksum", "GRE checksum mismatch")
                    .at_field("checksum"),
            );
        }
        let layer = Gre {
            protocol_type: WireValue::Exact(protocol_type),
            checksum: checksum_value,
            key,
            sequence,
            reserved_bits,
        };
        let payload_len = input.len() - header_len;
        Ok(DecodedLayerValue {
            fields: gre_layout(&layer),
            layer: Box::new(layer),
            consumed: header_len,
            payload_offset: header_len,
            payload_len,
            next: vec![Discriminator(u64::from(protocol_type))],
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Gre::default(), fields)
    }
}

fn gre_layout(layer: &Gre) -> Vec<crate::packet::layout::FieldLayout> {
    // Optional GRE fields move according to the preceding presence bits, so
    // only the fixed prefix is generated from the field declaration.
    let mut fields = gre_static_layout();
    let mut cursor = GRE_BASE_LEN;
    if layer.checksum.is_some() {
        fields.push(gre_dynamic_field("checksum", cursor, cursor + 2));
        cursor += GRE_OPTION_LEN;
    }
    if layer.key.is_some() {
        fields.push(gre_dynamic_field("key", cursor, cursor + GRE_OPTION_LEN));
        cursor += GRE_OPTION_LEN;
    }
    if layer.sequence.is_some() {
        fields.push(gre_dynamic_field(
            "sequence",
            cursor,
            cursor + GRE_OPTION_LEN,
        ));
    }
    fields
}

fn gre_dynamic_field(name: &str, start: usize, end: usize) -> crate::packet::layout::FieldLayout {
    crate::packet::layout::FieldLayout {
        name: name.to_owned(),
        range: crate::packet::layout::ByteRange::new(start, end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        Packet,
        build::{BuildContext, BuildMode},
        registry::ProtocolRegistry,
    };

    fn decode_context(
        registry: &ProtocolRegistry,
        verify_checksums: bool,
    ) -> LayerDecodeContext<'_> {
        LayerDecodeContext {
            registry,
            layer_index: 0,
            absolute_offset: 0,
            verify_checksums,
            allow_trailing_padding: false,
            network: None,
        }
    }

    #[test]
    fn version_zero_options_decode_in_wire_order_and_select_ethertype_child() {
        let payload = [0xde, 0xad, 0xbe, 0xef, 0x01];
        let mut bytes = vec![
            0xb0, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        bytes.extend_from_slice(&payload);
        let checksum_value = checksum(&bytes);
        bytes[4..6].copy_from_slice(&checksum_value.to_be_bytes());
        let registry = ProtocolRegistry::default();

        let decoded = GreCodec
            .decode(&bytes, &decode_context(&registry, true))
            .unwrap();
        let gre = decoded.layer.as_any().downcast_ref::<Gre>().unwrap();

        assert_eq!(decoded.consumed, 16);
        assert_eq!(decoded.payload_len, payload.len());
        assert_eq!(decoded.next, vec![Discriminator(0x0800)]);
        assert!(decoded.diagnostics.is_empty());
        assert_eq!(gre.protocol_type, WireValue::Exact(0x0800));
        assert_eq!(gre.checksum, Some(WireValue::Exact(checksum_value)));
        assert_eq!(gre.key, Some(0x1122_3344));
        assert_eq!(gre.sequence, Some(0x5566_7788));
    }

    #[test]
    fn decode_rejects_routing_versions_reserved_flags_and_reserved1() {
        let registry = ProtocolRegistry::default();
        for bytes in [
            [0x40, 0x00, 0x08, 0x00],
            [0x00, 0x01, 0x08, 0x00],
            [0x08, 0x00, 0x08, 0x00],
        ] {
            assert!(matches!(
                GreCodec.decode(&bytes, &decode_context(&registry, false)),
                Err(CodecError::Unsupported { .. })
            ));
        }
        assert!(matches!(
            GreCodec.decode(
                &[0x80, 0, 0x08, 0, 0, 0, 0, 1],
                &decode_context(&registry, false)
            ),
            Err(CodecError::Invalid { .. })
        ));
    }

    #[test]
    fn decode_preserves_receiver_ignored_reserved_bits() {
        let registry = ProtocolRegistry::default();
        let decoded = GreCodec
            .decode(&[0x03, 0xf8, 0x08, 0x00], &decode_context(&registry, false))
            .unwrap();
        let gre = decoded.layer.as_any().downcast_ref::<Gre>().unwrap();

        assert_eq!(gre.reserved_bits, 0x7f);
        assert_eq!(decoded.diagnostics.len(), 1);
        assert_eq!(decoded.diagnostics[0].code, "decode.gre_reserved_bits");
    }

    #[test]
    fn encode_requires_permissive_mode_for_receiver_ignored_reserved_bits() {
        let gre = Gre {
            protocol_type: WireValue::Exact(0x0800),
            reserved_bits: 0x7f,
            ..Gre::default()
        };
        let mut packet = Packet::new();
        packet.push(gre.clone());
        let registry = ProtocolRegistry::default();
        let build_context = BuildContext::default();
        let encode = |mode| {
            GreCodec.encode(
                &gre,
                &[],
                &LayerEncodeContext {
                    packet: &packet,
                    index: 0,
                    build_context: &build_context,
                    mode,
                    registry: &registry,
                    child: None,
                    remaining_packet_bytes: GRE_BASE_LEN,
                },
            )
        };

        assert!(matches!(
            encode(BuildMode::Strict),
            Err(CodecError::Invalid { .. })
        ));
        let permissive = encode(BuildMode::Permissive).unwrap();
        assert_eq!(&permissive.prefix[..2], &[0x03, 0xf8]);
        assert_eq!(permissive.diagnostics[0].code, "build.gre_reserved_bits");
    }

    #[test]
    fn encode_derives_flags_checksum_and_zero_reserved1() {
        let gre = Gre {
            protocol_type: WireValue::Exact(0x86dd),
            checksum: Some(WireValue::Auto),
            key: Some(7),
            sequence: Some(9),
            reserved_bits: 0,
        };
        let payload = [1, 2, 3, 4, 5];
        let mut packet = Packet::new();
        packet.push(gre.clone());
        let registry = ProtocolRegistry::default();
        let build_context = BuildContext::default();
        let encoded = GreCodec
            .encode(
                &gre,
                &payload,
                &LayerEncodeContext {
                    packet: &packet,
                    index: 0,
                    build_context: &build_context,
                    mode: BuildMode::Strict,
                    registry: &registry,
                    child: None,
                    remaining_packet_bytes: 16,
                },
            )
            .unwrap();

        assert_eq!(&encoded.prefix[..4], &[0xb0, 0, 0x86, 0xdd]);
        assert_eq!(&encoded.prefix[6..8], &[0, 0]);
        assert_eq!(&encoded.prefix[8..12], &7_u32.to_be_bytes());
        assert_eq!(&encoded.prefix[12..16], &9_u32.to_be_bytes());
        assert_eq!(checksum_parts(&[&encoded.prefix, &payload]), 0);
        let materialized = encoded.materialized.as_any().downcast_ref::<Gre>().unwrap();
        assert!(matches!(materialized.checksum, Some(WireValue::Exact(_))));
    }

    #[test]
    fn exact_checksum_mismatch_follows_strict_and_permissive_conventions() {
        let gre = Gre {
            protocol_type: WireValue::Exact(0x0800),
            checksum: Some(WireValue::Exact(1)),
            key: None,
            sequence: None,
            reserved_bits: 0,
        };
        let mut packet = Packet::new();
        packet.push(gre.clone());
        let registry = ProtocolRegistry::default();
        let build_context = BuildContext::default();
        let encode = |mode| {
            GreCodec.encode(
                &gre,
                &[1, 2, 3],
                &LayerEncodeContext {
                    packet: &packet,
                    index: 0,
                    build_context: &build_context,
                    mode,
                    registry: &registry,
                    child: None,
                    remaining_packet_bytes: 8,
                },
            )
        };

        assert!(matches!(
            encode(BuildMode::Strict),
            Err(CodecError::Invalid { .. })
        ));
        let permissive = encode(BuildMode::Permissive).unwrap();
        assert_eq!(&permissive.prefix[4..6], &1_u16.to_be_bytes());
        assert!(
            permissive
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "build.inconsistent_dependent_field")
        );
    }

    #[test]
    fn encode_rejects_optional_header_before_exceeding_packet_budget() {
        let gre = Gre {
            checksum: Some(WireValue::Auto),
            key: Some(1),
            sequence: Some(2),
            ..Gre::default()
        };
        let mut packet = Packet::new();
        packet.push(gre.clone());
        let registry = ProtocolRegistry::default();
        let build_context = BuildContext::default();

        assert!(matches!(
            GreCodec.encode(
                &gre,
                &[],
                &LayerEncodeContext {
                    packet: &packet,
                    index: 0,
                    build_context: &build_context,
                    mode: BuildMode::Strict,
                    registry: &registry,
                    child: None,
                    remaining_packet_bytes: 15,
                }
            ),
            Err(CodecError::Invalid { .. })
        ));
    }
}
