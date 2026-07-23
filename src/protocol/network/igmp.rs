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
    payload_without_padding, protocol, resolve_u16, truncated, wrong_layer,
};

const IGMP_HEADER_LEN: usize = 4;
const IGMP_MIN_LEN: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmp {
    pub igmp_type: u8,
    pub code: u8,
    pub checksum: WireValue<u16>,
    pub body: Bytes,
}

impl Default for Igmp {
    fn default() -> Self {
        Self {
            igmp_type: 0x11,
            code: 0,
            checksum: WireValue::Auto,
            body: Bytes::from_static(&[0, 0, 0, 0]),
        }
    }
}

reflective_layer! {
    fn igmp_schema() => { protocol: protocol("igmp"), name: "IGMP" }
    impl Igmp {
        "type" => {
            kind: Unsigned, derived: false, required: true,
            description: "IGMP message type",
            get |layer| Some(reflect_get(&layer.igmp_type)),
            set |layer, value, name| reflect_set(&mut layer.igmp_type, igmp_schema(), name, value),
            layout: (0, 1)
        },
        "code" => {
            kind: Unsigned, derived: false, required: true,
            description: "Type-specific IGMP code or reserved octet",
            get |layer| Some(reflect_get(&layer.code)),
            set |layer, value, name| reflect_set(&mut layer.code, igmp_schema(), name, value),
            layout: (1, 2)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false,
            description: "IGMP checksum",
            get |layer| Some(reflect_get(&layer.checksum)),
            set |layer, value, name| reflect_set(&mut layer.checksum, igmp_schema(), name, value),
            layout: (2, 4)
        },
        "body" => {
            kind: Bytes, derived: false, required: false,
            description: "Version- and type-specific IGMP body",
            get |layer| Some(reflect_get(&layer.body)),
            set |layer, value, name| reflect_set(&mut layer.body, igmp_schema(), name, value),
            layout: (4, 4 + body_len)
        },
        normalize |layer| { layer.checksum.normalize(); }
    }
    layout fn igmp_layout(body_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IgmpCodec;

impl LayerCodec for IgmpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("igmp")
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
            .downcast_ref::<Igmp>()
            .ok_or_else(|| wrong_layer("igmp", layer))?;
        let contribution = IGMP_HEADER_LEN
            .checked_add(layer.body.len())
            .ok_or_else(|| invalid("igmp", "message length overflow"))?;
        if contribution < IGMP_MIN_LEN {
            return Err(invalid(
                "igmp",
                format!("message length {contribution} is below the 8-byte minimum"),
            ));
        }
        ensure_encode_budget("igmp", contribution, context)?;

        let mut prefix = Vec::with_capacity(contribution);
        prefix.extend_from_slice(&[layer.igmp_type, layer.code, 0, 0]);
        prefix.extend_from_slice(&layer.body);
        let covered_payload = payload_without_padding("igmp", payload, context)?;
        let expected = checksum_parts(&[&prefix, covered_payload]);
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            "igmp",
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
            fields: igmp_layout(layer.body.len()),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < IGMP_MIN_LEN {
            return Err(truncated("igmp", IGMP_MIN_LEN, input.len()));
        }
        let mut diagnostics = Vec::new();
        if context.verify_checksums && checksum(input) != 0 {
            diagnostics.push(
                Diagnostic::warning("decode.igmp_checksum", "IGMP checksum mismatch")
                    .at_field("checksum"),
            );
        }
        Ok(DecodedLayerValue {
            layer: Box::new(Igmp {
                igmp_type: input[0],
                code: input[1],
                checksum: WireValue::Exact(u16::from_be_bytes([input[2], input[3]])),
                body: Bytes::copy_from_slice(&input[IGMP_HEADER_LEN..]),
            }),
            consumed: input.len(),
            payload_offset: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: igmp_layout(input.len() - IGMP_HEADER_LEN),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Igmp::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use super::*;
    use crate::packet::{
        Packet,
        build::{BuildContext, BuildMode, BuildOptions, Builder},
        decode::{DecodeOptions, Dissector},
        layer::Raw,
        registry::ProtocolRegistry,
    };
    use crate::protocol::network::Ipv4;

    fn encode(layer: &Igmp, mode: BuildMode) -> Result<EncodedLayer, CodecError> {
        let packet = Packet::new();
        let build_context = BuildContext::default();
        let registry = ProtocolRegistry::default();
        IgmpCodec.encode(
            layer,
            &[],
            &LayerEncodeContext {
                packet: &packet,
                index: 0,
                build_context: &build_context,
                mode,
                registry: &registry,
                child: None,
                remaining_packet_bytes: usize::MAX,
            },
        )
    }

    fn decode(input: &[u8], verify_checksums: bool) -> Result<DecodedLayerValue, CodecError> {
        let registry = ProtocolRegistry::default();
        IgmpCodec.decode(
            input,
            &LayerDecodeContext {
                registry: &registry,
                layer_index: 0,
                absolute_offset: 0,
                verify_checksums,
                allow_trailing_padding: false,
                network: None,
            },
        )
    }

    #[test]
    fn default_encodes_valid_membership_query() {
        let encoded = encode(&Igmp::default(), BuildMode::Strict).unwrap();

        assert_eq!(encoded.prefix, [0x11, 0x00, 0xee, 0xff, 0, 0, 0, 0]);
        assert_eq!(checksum(&encoded.prefix), 0);
        assert_eq!(
            encoded
                .materialized
                .as_any()
                .downcast_ref::<Igmp>()
                .unwrap()
                .checksum,
            WireValue::Exact(0xeeff)
        );
    }

    #[test]
    fn messages_shorter_than_eight_bytes_are_rejected() {
        let short = Igmp {
            body: Bytes::from_static(&[0, 0, 0]),
            ..Igmp::default()
        };

        assert!(matches!(
            encode(&short, BuildMode::Strict),
            Err(CodecError::Invalid { .. })
        ));
        assert!(matches!(
            decode(&[0; 7], false),
            Err(CodecError::Truncated {
                needed: 8,
                available: 7,
                ..
            })
        ));
    }

    #[test]
    fn exact_checksum_mismatch_is_strict_or_diagnostic() {
        let layer = Igmp {
            checksum: WireValue::Exact(0),
            ..Igmp::default()
        };

        assert!(matches!(
            encode(&layer, BuildMode::Strict),
            Err(CodecError::Invalid { .. })
        ));
        let encoded = encode(&layer, BuildMode::Permissive).unwrap();
        assert_eq!(&encoded.prefix[2..4], &[0, 0]);
        assert_eq!(encoded.diagnostics.len(), 1);
        assert_eq!(
            encoded.diagnostics[0].code,
            "build.inconsistent_dependent_field"
        );
        assert_eq!(encoded.diagnostics[0].field.as_deref(), Some("checksum"));
    }

    #[test]
    fn decode_preserves_variable_bodies_losslessly() {
        for body in [
            Bytes::from_static(&[224, 0, 0, 1]),
            Bytes::from_static(&[0, 0, 0, 0, 2, 10, 0, 0]),
            Bytes::from_static(&[239, 1, 2, 3, 0, 0, 0, 1, 192, 0, 2, 1]),
        ] {
            let original = Igmp {
                body: body.clone(),
                ..Igmp::default()
            };
            let encoded = encode(&original, BuildMode::Strict).unwrap();
            let decoded = decode(&encoded.prefix, true).unwrap();
            let decoded_layer = decoded.layer.as_any().downcast_ref::<Igmp>().unwrap();

            assert_eq!(decoded_layer.body, body);
            assert!(decoded.diagnostics.is_empty());
            assert_eq!(
                encode(decoded_layer, BuildMode::Strict).unwrap().prefix,
                encoded.prefix
            );
        }
    }

    #[test]
    fn decode_reports_checksum_mismatch() {
        let decoded = decode(&[0x11, 0, 0, 0, 0, 0, 0, 0], true).unwrap();

        assert_eq!(decoded.diagnostics.len(), 1);
        assert_eq!(decoded.diagnostics[0].code, "decode.igmp_checksum");
        assert_eq!(decoded.diagnostics[0].field.as_deref(), Some("checksum"));
    }

    #[test]
    fn permissive_terminal_payload_is_covered_by_the_checksum() {
        let registry = Arc::new(crate::protocol::builtin::registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(224, 0, 0, 1),
                ..Ipv4::default()
            })
            .push(Igmp::default())
            .push(Raw::new(vec![1, 2, 3]));

        assert!(
            builder
                .build(
                    packet.clone(),
                    BuildContext::default(),
                    BuildOptions::default(),
                )
                .is_err()
        );
        let built = builder
            .build(
                packet,
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .unwrap();
        assert_eq!(checksum(&built.bytes[20..]), 0);
        let decoded = Dissector::new(registry)
            .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
            .unwrap();

        assert_eq!(decoded.packet.get::<Igmp>().unwrap().body.len(), 7);
        assert!(
            decoded
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.code != "decode.igmp_checksum")
        );
    }
}
