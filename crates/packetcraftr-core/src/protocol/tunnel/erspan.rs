// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, reflect_get, reflect_set_bounded, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ensure_encode_budget, invalid, make_layer, out_of_range, protocol, strict_or_diagnostic,
    truncated, validate_raw_child_discriminator, wrong_layer, wrong_type,
};

const ERSPAN_II_LEN: usize = 8;
const ERSPAN_III_LEN: usize = 12;
const SUBHEADER_LEN: usize = 8;
/// The O bit of the Type III flag word: an optional subheader follows.
const SUBHEADER_FLAG: u16 = 0x0001;
/// GRE protocol type carrying a Type II header.
const TYPE_II_PROTOCOL: u64 = 0x88be;
/// GRE protocol type carrying a Type III header.
const TYPE_III_PROTOCOL: u64 = 0x22eb;

/// ERSPAN mirrored-frame header, Type II (version 1) or Type III (version 2).
///
/// Both types end in the mirrored Ethernet frame. The Type III extras are
/// grouped in [`ErspanType3`], present exactly when `version` is 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Erspan {
    /// Header version: 1 is Type II, 2 is Type III.
    pub version: u8,
    /// VLAN of the mirrored frame.
    pub vlan: u16,
    /// Class of service of the mirrored frame.
    pub cos: u8,
    /// Type II: trunk encapsulation type. Type III: bad/short frame bits.
    pub encapsulation: u8,
    /// The mirrored frame was truncated by the session MTU.
    pub truncated: bool,
    /// 10-bit monitoring-session identifier.
    pub session_id: u16,
    /// Type II: reserved 12 bits and the 20-bit port index, packed as the
    /// final word. Type III leaves this zero.
    pub index_word: u32,
    /// Type III extras; present exactly when `version` is 2.
    pub type3: Option<ErspanType3>,
}

/// The Type III fields between the session word and the mirrored frame.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ErspanType3 {
    /// Wire-format timestamp.
    pub timestamp: u32,
    /// Security group tag.
    pub sgt: u16,
    /// The final half-word: P bit, frame type, hardware ID, direction,
    /// timestamp granularity, and the optional-subheader flag.
    pub flags: u16,
    /// The 8-byte platform-specific subheader; present exactly when the
    /// flag word's O bit is set.
    pub subheader: Option<Bytes>,
}

impl Default for Erspan {
    fn default() -> Self {
        Self {
            version: 1,
            vlan: 0,
            cos: 0,
            encapsulation: 0,
            truncated: false,
            session_id: 0,
            index_word: 0,
            type3: None,
        }
    }
}

reflective_layer! {
    fn erspan_schema() => { protocol: protocol("erspan"), name: "ERSPAN" }
    impl Erspan {
        "version" => { kind: Unsigned, derived: false, required: true, description: "Header version: 1 is Type II, 2 is Type III", get |layer| Some(reflect_get(&layer.version)), set |layer, value, name| { reflect_set_bounded(&mut layer.version, erspan_schema(), name, value, 0xf_u64)?; if layer.version == 2 && layer.type3.is_none() { layer.type3 = Some(ErspanType3::default()); } Ok(()) }, layout: (0, 2) },
        "vlan" => { kind: Unsigned, derived: false, required: false, description: "VLAN of the mirrored frame", reflect_bounded: vlan, 0xfff_u64, layout: (0, 2) },
        "cos" => { kind: Unsigned, derived: false, required: false, description: "Class of service of the mirrored frame", reflect_bounded: cos, 7_u64, layout: (2, 4) },
        "encapsulation" => { kind: Unsigned, derived: false, required: false, description: "Type II trunk encapsulation; Type III bad/short frame bits", reflect_bounded: encapsulation, 3_u64, layout: (2, 4) },
        "truncated" => { kind: Bool, derived: false, required: false, description: "The mirrored frame was truncated by the session MTU", reflect: truncated, layout: (2, 4) },
        "session_id" => { kind: Unsigned, derived: false, required: true, description: "10-bit monitoring-session identifier", reflect_bounded: session_id, 0x3ff_u64, layout: (2, 4) },
        "index_word" => { kind: Unsigned, derived: false, required: false, description: "Type II reserved bits and port index, packed as the final word", reflect: index_word, layout: (4, 8) },
        "timestamp" => { kind: Unsigned, derived: false, required: false, description: "Type III wire-format timestamp", get |layer| layer.type3.as_ref().map(|type3| FieldValue::from(type3.timestamp)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.type3.get_or_insert_with(ErspanType3::default).timestamp = u32::try_from(value).map_err(|_| out_of_range(erspan_schema(), name))?; Ok(()) }, _ => Err(wrong_type(erspan_schema(), name, "unsigned")) } },
        "sgt" => { kind: Unsigned, derived: false, required: false, description: "Type III security group tag", get |layer| layer.type3.as_ref().map(|type3| FieldValue::from(type3.sgt)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.type3.get_or_insert_with(ErspanType3::default).sgt = u16::try_from(value).map_err(|_| out_of_range(erspan_schema(), name))?; Ok(()) }, _ => Err(wrong_type(erspan_schema(), name, "unsigned")) } },
        "flags" => { kind: Unsigned, derived: false, required: false, description: "Type III flag half-word: P bit, frame type, hardware ID, direction, granularity, and the subheader O bit", get |layer| layer.type3.as_ref().map(|type3| FieldValue::from(type3.flags)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.type3.get_or_insert_with(ErspanType3::default).flags = u16::try_from(value).map_err(|_| out_of_range(erspan_schema(), name))?; Ok(()) }, _ => Err(wrong_type(erspan_schema(), name, "unsigned")) } },
        "subheader" => { kind: Bytes, derived: false, required: false, description: "Type III 8-byte platform-specific subheader", get |layer| layer.type3.as_ref().and_then(|type3| type3.subheader.clone()).map(FieldValue::Bytes), set |layer, value, name| match value { FieldValue::Bytes(value) => { layer.type3.get_or_insert_with(ErspanType3::default).subheader = Some(value); Ok(()) }, _ => Err(wrong_type(erspan_schema(), name, "bytes")) } }
    }
    layout pub(crate) fn erspan_static_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ErspanCodec;

impl LayerCodec for ErspanCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("erspan")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = layer
            .as_any()
            .downcast_ref::<Erspan>()
            .ok_or_else(|| wrong_layer("erspan", layer))?;
        let header_len = validate_shape(layer, context)?;
        let diagnostics = validate_parent(layer, context)?;

        let mut prefix = Vec::with_capacity(header_len);
        let first = (u16::from(layer.version) << 12) | layer.vlan;
        prefix.extend_from_slice(&first.to_be_bytes());
        let second = (u16::from(layer.cos) << 13)
            | (u16::from(layer.encapsulation) << 11)
            | (u16::from(layer.truncated) << 10)
            | layer.session_id;
        prefix.extend_from_slice(&second.to_be_bytes());
        if let Some(type3) = &layer.type3 {
            prefix.extend_from_slice(&type3.timestamp.to_be_bytes());
            prefix.extend_from_slice(&type3.sgt.to_be_bytes());
            prefix.extend_from_slice(&type3.flags.to_be_bytes());
            if let Some(subheader) = &type3.subheader {
                prefix.extend_from_slice(subheader);
            }
        } else {
            prefix.extend_from_slice(&layer.index_word.to_be_bytes());
        }
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(layer.clone()),
            fields: erspan_layout(layer),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(base) = input.first_chunk::<ERSPAN_II_LEN>() else {
            return Err(truncated("erspan", ERSPAN_II_LEN, input.len()));
        };
        let first = u16::from_be_bytes([base[0], base[1]]);
        let version = (first >> 12) as u8;
        let mut type3_header = None;
        let header_len = match version {
            1 => ERSPAN_II_LEN,
            2 => {
                let Some(header) = input.first_chunk::<ERSPAN_III_LEN>() else {
                    return Err(truncated("erspan", ERSPAN_III_LEN, input.len()));
                };
                type3_header = Some(header);
                // The flag word's O bit places an 8-byte subheader before
                // the mirrored frame.
                if u16::from_be_bytes([header[10], header[11]]) & SUBHEADER_FLAG != 0 {
                    ERSPAN_III_LEN.saturating_add(SUBHEADER_LEN)
                } else {
                    ERSPAN_III_LEN
                }
            }
            other => {
                return Err(crate::codec::Error::Unsupported {
                    protocol: protocol("erspan"),
                    message: format!("ERSPAN version {other} is not supported"),
                });
            }
        };
        if input.len() < header_len {
            return Err(truncated("erspan", header_len, input.len()));
        }
        let second = u16::from_be_bytes([base[2], base[3]]);

        let mut diagnostics = Vec::new();
        // The GRE protocol type is authoritative for the expected header
        // type; a version that disagrees is preserved but flagged.
        let expected_version = match context.discriminator.map(|discriminator| discriminator.0) {
            Some(TYPE_II_PROTOCOL) => Some(1),
            Some(TYPE_III_PROTOCOL) => Some(2),
            _ => None,
        };
        if expected_version.is_some_and(|expected| expected != version) {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.erspan_type",
                    "the header version disagrees with the enclosing GRE protocol type",
                )
                .at_field("version"),
            );
        }
        let (index_word, type3) = if let Some(header) = type3_header {
            (
                0,
                Some(ErspanType3 {
                    timestamp: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                    sgt: u16::from_be_bytes([header[8], header[9]]),
                    flags: u16::from_be_bytes([header[10], header[11]]),
                    subheader: if header_len > ERSPAN_III_LEN {
                        input
                            .get(ERSPAN_III_LEN..header_len)
                            .map(Bytes::copy_from_slice)
                    } else {
                        None
                    },
                }),
            )
        } else {
            (
                u32::from_be_bytes([base[4], base[5], base[6], base[7]]),
                None,
            )
        };
        let layer = Erspan {
            version,
            vlan: first & 0xfff,
            cos: (second >> 13) as u8,
            encapsulation: ((second >> 11) & 0x3) as u8,
            truncated: second & 0x400 != 0,
            session_id: second & 0x3ff,
            index_word,
            type3,
        };
        let payload_len = input.len().saturating_sub(header_len);
        let fields = erspan_layout(&layer);
        Ok(DecodedLayerValue {
            fields,
            layer: Box::new(layer),
            consumed: header_len,
            payload_len,
            // The mirrored frame is always Ethernet.
            next: vec![Discriminator(0)],
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Erspan::default(), fields)
    }
}

fn validate_shape(
    layer: &Erspan,
    context: &LayerEncodeContext<'_>,
) -> Result<usize, crate::codec::Error> {
    let header_len = match layer.version {
        1 => ERSPAN_II_LEN,
        2 => {
            let subheader_len = layer
                .type3
                .as_ref()
                .and_then(|type3| type3.subheader.as_ref())
                .map_or(0, Bytes::len);
            ERSPAN_III_LEN.saturating_add(subheader_len)
        }
        other => {
            return Err(invalid(
                "erspan",
                format!("version {other} is not a known ERSPAN header type"),
            ));
        }
    };
    ensure_encode_budget("erspan", header_len, context)?;
    if layer.vlan > 0xfff || layer.cos > 7 || layer.encapsulation > 3 || layer.session_id > 0x3ff {
        return Err(invalid("erspan", "field exceeds its wire range"));
    }
    if (layer.version == 2) != layer.type3.is_some() {
        return Err(invalid(
            "erspan",
            "Type III fields are present exactly when the version is 2",
        ));
    }
    if let Some(type3) = &layer.type3 {
        match (&type3.subheader, type3.flags & SUBHEADER_FLAG != 0) {
            (Some(subheader), true) if subheader.len() != SUBHEADER_LEN => {
                return Err(invalid(
                    "erspan",
                    format!("the optional subheader is exactly {SUBHEADER_LEN} bytes"),
                ));
            }
            (Some(_), false) => {
                return Err(invalid(
                    "erspan",
                    "a subheader requires the flag word's O bit",
                ));
            }
            (None, true) => {
                return Err(invalid(
                    "erspan",
                    "the flag word's O bit requires the 8-byte subheader",
                ));
            }
            _ => {}
        }
    }
    Ok(header_len)
}

fn validate_parent(
    layer: &Erspan,
    context: &LayerEncodeContext<'_>,
) -> Result<Vec<Diagnostic>, crate::codec::Error> {
    let mut diagnostics = Vec::new();
    if layer.version == 2 && layer.index_word != 0 {
        strict_or_diagnostic(
            "erspan",
            "build.erspan_index",
            "index_word",
            "the index word belongs to Type II headers only",
            context,
            &mut diagnostics,
        )?;
    }
    let expected_protocol_type = if layer.version == 1 {
        TYPE_II_PROTOCOL
    } else {
        TYPE_III_PROTOCOL
    };
    let parent = context
        .index
        .checked_sub(1)
        .and_then(|index| context.packet.layer(index));
    let protocol_type_disagrees = match parent.and_then(|layer| layer.field("protocol_type")) {
        Some(FieldValue::Unsigned(value @ (TYPE_II_PROTOCOL | TYPE_III_PROTOCOL))) => {
            value != expected_protocol_type
        }
        Some(FieldValue::Text(_)) => layer.version != 1,
        _ => false,
    };
    if protocol_type_disagrees {
        strict_or_diagnostic(
            "erspan",
            "build.erspan_type",
            "version",
            format!(
                "version {} requires the enclosing GRE protocol type 0x{expected_protocol_type:04x}",
                layer.version
            ),
            context,
            &mut diagnostics,
        )?;
    }
    if layer.version == 1
        && parent.is_some_and(|parent| {
            parent.protocol_id().as_str() == "gre" && parent.field("sequence").is_none()
        })
    {
        strict_or_diagnostic(
            "erspan",
            "build.erspan_sequence",
            "version",
            "Type II encapsulation requires the GRE sequence field",
            context,
            &mut diagnostics,
        )?;
    }
    validate_raw_child_discriminator("erspan", 0, context, &mut diagnostics)?;
    Ok(diagnostics)
}

fn erspan_layout(layer: &Erspan) -> Vec<crate::layout::FieldLayout> {
    let mut fields = erspan_static_layout();
    if let Some(type3) = &layer.type3 {
        // The index word does not exist in a Type III header; its slot is
        // the timestamp, the trailing flag word, and the optional subheader.
        fields.retain(|field| field.name != "index_word");
        for (name, start, end) in [("timestamp", 4, 8), ("sgt", 8, 10), ("flags", 10, 12)] {
            fields.push(crate::layout::FieldLayout {
                name: name.to_owned(),
                range: crate::layout::ByteRange::new(start, end),
            });
        }
        if type3.subheader.is_some() {
            fields.push(crate::layout::FieldLayout {
                name: "subheader".to_owned(),
                range: crate::layout::ByteRange::new(
                    ERSPAN_III_LEN,
                    ERSPAN_III_LEN.saturating_add(SUBHEADER_LEN),
                ),
            });
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;
    use crate::Packet;
    use crate::protocol::link::Ethernet;

    fn encode(
        layer: &Erspan,
        mode: crate::build::Mode,
        remaining_packet_bytes: usize,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry().expect("built-in registry");
        let packet = Packet::new();
        let build_context = crate::build::Context::default();
        let child = Ethernet::default();
        let context = LayerEncodeContext {
            packet: &packet,
            index: 0,
            build_context: &build_context,
            mode,
            registry: &registry,
            child: Some(&child),
            remaining_packet_bytes,
        };
        ErspanCodec.encode(layer, &[], &context)
    }

    fn decode(
        input: &[u8],
        discriminator: Option<u64>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry().expect("built-in registry");
        let context = LayerDecodeContext {
            registry: &registry,
            layer_index: 0,
            absolute_offset: 0,
            verify_checksums: true,
            allow_trailing_padding: false,
            network: None,
            discriminator: discriminator.map(Discriminator),
        };
        ErspanCodec.decode(input, &context)
    }

    fn decode_error(input: &[u8]) -> crate::codec::Error {
        match decode(input, None) {
            Ok(_) => panic!("ERSPAN vector unexpectedly decoded: {input:02x?}"),
            Err(error) => error,
        }
    }

    fn encode_error(layer: &Erspan) -> crate::codec::Error {
        match encode(layer, crate::build::Mode::Strict, usize::MAX) {
            Ok(_) => panic!("invalid ERSPAN layer unexpectedly encoded: {layer:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn type_two_header_has_an_exact_wire_image_and_round_trips_all_fields() {
        let layer = Erspan {
            version: 1,
            vlan: 0xabc,
            cos: 5,
            encapsulation: 2,
            truncated: true,
            session_id: 0x155,
            index_word: 0x1234_5678,
            type3: None,
        };

        let encoded = encode(&layer, crate::build::Mode::Strict, ERSPAN_II_LEN).unwrap();
        assert_eq!(
            encoded.prefix,
            [0x1a, 0xbc, 0xb5, 0x55, 0x12, 0x34, 0x56, 0x78]
        );
        assert!(encoded.diagnostics.is_empty());

        let decoded = decode(&encoded.prefix, Some(TYPE_II_PROTOCOL)).unwrap();
        assert_eq!(decoded.consumed, ERSPAN_II_LEN);
        assert_eq!(decoded.payload_len, 0);
        assert!(decoded.stop);
        assert!(decoded.diagnostics.is_empty());
        assert_eq!(decoded.next, [Discriminator(0)]);
        assert_eq!(
            decoded.layer.as_any().downcast_ref::<Erspan>(),
            Some(&layer)
        );
    }

    #[test]
    fn type_three_optional_subheader_round_trips_and_has_precise_layout() {
        let subheader = Bytes::from_static(b"PCR-TEST");
        let layer = Erspan {
            version: 2,
            vlan: 0x123,
            cos: 3,
            encapsulation: 1,
            truncated: false,
            session_id: 0x2aa,
            index_word: 0,
            type3: Some(ErspanType3 {
                timestamp: 0x0102_0304,
                sgt: 0x0506,
                flags: SUBHEADER_FLAG,
                subheader: Some(subheader.clone()),
            }),
        };

        let encoded = encode(&layer, crate::build::Mode::Strict, 20).unwrap();
        assert_eq!(
            encoded.prefix,
            [
                0x21, 0x23, 0x6a, 0xaa, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, b'P', b'C',
                b'R', b'-', b'T', b'E', b'S', b'T',
            ]
        );
        assert_eq!(
            encoded
                .fields
                .iter()
                .find(|field| field.name == "subheader")
                .map(|field| field.range),
            Some(crate::layout::ByteRange::new(12, 20))
        );
        assert!(
            !encoded
                .fields
                .iter()
                .any(|field| field.name == "index_word")
        );

        let decoded = decode(&encoded.prefix, Some(TYPE_III_PROTOCOL)).unwrap();
        assert_eq!(decoded.consumed, 20);
        assert_eq!(
            decoded.layer.as_any().downcast_ref::<Erspan>(),
            Some(&layer)
        );
    }

    #[test]
    fn decoder_distinguishes_base_type_three_and_optional_subheader_truncation() {
        assert!(matches!(
            decode_error(&[0; 7]),
            crate::codec::Error::Truncated {
                needed: 8,
                available: 7,
                ..
            }
        ));

        let mut short_type_three = [0_u8; 8];
        short_type_three[0] = 0x20;
        assert!(matches!(
            decode_error(&short_type_three),
            crate::codec::Error::Truncated {
                needed: 12,
                available: 8,
                ..
            }
        ));

        let mut short_subheader = [0_u8; 12];
        short_subheader[0] = 0x20;
        short_subheader[11] = 1;
        assert!(matches!(
            decode_error(&short_subheader),
            crate::codec::Error::Truncated {
                needed: 20,
                available: 12,
                ..
            }
        ));

        assert!(matches!(
            decode_error(&[0; 8]),
            crate::codec::Error::Unsupported { .. }
        ));
    }

    #[test]
    fn enclosing_gre_discriminator_mismatch_is_retained_as_a_decode_diagnostic() {
        let type_two = [0x10, 0, 0, 0, 0, 0, 0, 0];
        let decoded = decode(&type_two, Some(TYPE_III_PROTOCOL)).unwrap();
        assert_eq!(decoded.diagnostics.len(), 1);
        assert_eq!(decoded.diagnostics[0].code, "decode.erspan_type");
        assert_eq!(decoded.diagnostics[0].field.as_deref(), Some("version"));
    }

    #[test]
    fn encoder_rejects_version_shape_subheader_range_and_budget_mismatches() {
        let type_three = || Erspan {
            version: 2,
            type3: Some(ErspanType3::default()),
            ..Erspan::default()
        };
        let cases = [
            (
                Erspan {
                    version: 3,
                    ..Erspan::default()
                },
                "not a known ERSPAN header type",
            ),
            (
                Erspan {
                    vlan: 0x1000,
                    ..Erspan::default()
                },
                "field exceeds its wire range",
            ),
            (
                Erspan {
                    version: 2,
                    type3: None,
                    ..Erspan::default()
                },
                "present exactly when the version is 2",
            ),
            (
                Erspan {
                    type3: Some(ErspanType3::default()),
                    ..Erspan::default()
                },
                "present exactly when the version is 2",
            ),
            (
                Erspan {
                    type3: Some(ErspanType3 {
                        flags: SUBHEADER_FLAG,
                        subheader: Some(Bytes::from_static(b"short")),
                        ..ErspanType3::default()
                    }),
                    ..type_three()
                },
                "exactly 8 bytes",
            ),
            (
                Erspan {
                    type3: Some(ErspanType3 {
                        subheader: Some(Bytes::from_static(b"12345678")),
                        ..ErspanType3::default()
                    }),
                    ..type_three()
                },
                "subheader requires the flag word's O bit",
            ),
            (
                Erspan {
                    type3: Some(ErspanType3 {
                        flags: SUBHEADER_FLAG,
                        ..ErspanType3::default()
                    }),
                    ..type_three()
                },
                "O bit requires the 8-byte subheader",
            ),
        ];

        for (layer, expected) in cases {
            let error = encode_error(&layer);
            assert!(error.to_string().contains(expected), "{layer:?}: {error}");
        }

        let error = match encode(&Erspan::default(), crate::build::Mode::Strict, 7) {
            Ok(_) => panic!("undersized packet budget unexpectedly encoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("only 7 remain"));
    }

    #[test]
    fn type_three_index_word_is_strictly_rejected_or_permissively_diagnosed() {
        let layer = Erspan {
            version: 2,
            index_word: 1,
            type3: Some(ErspanType3::default()),
            ..Erspan::default()
        };
        assert!(
            encode_error(&layer)
                .to_string()
                .contains("Type II headers only")
        );

        let encoded = encode(&layer, crate::build::Mode::Permissive, 12).unwrap();
        assert_eq!(encoded.prefix.len(), 12);
        assert_eq!(encoded.diagnostics.len(), 1);
        assert_eq!(encoded.diagnostics[0].code, "build.erspan_index");
    }
}
