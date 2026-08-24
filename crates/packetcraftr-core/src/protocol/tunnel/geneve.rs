// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ensure_encode_budget, expected_discriminator, invalid, make_layer, protocol, resolve_u16,
    strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_raw_child_discriminator, wrong_layer,
};

const GENEVE_BASE_LEN: usize = 8;
/// Options length is a 6-bit count of 4-byte multiples.
const GENEVE_MAX_OPTIONS_LEN: usize = 0x3f * 4;
const OPTION_HEADER_LEN: usize = 4;
const CRITICAL_OPTION_FLAG: u8 = 0x80;
const VNI_MAX: u32 = 0x00ff_ffff;

/// GENEVE encapsulation header (RFC 8926).
///
/// The `protocol_type` EtherType selects the encapsulated frame — Transparent
/// Ethernet Bridging (0x6558), IPv4, or IPv6 — and the variable options are
/// carried verbatim so every captured chain rebuilds byte-for-byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geneve {
    /// 2-bit version; RFC 8926 defines only version 0.
    pub version: u8,
    /// The O bit: this is a control packet.
    pub control: bool,
    /// The C bit: one or more options are critical.
    pub critical: bool,
    /// Reserved 6 bits after the O and C bits.
    pub reserved1: u8,
    /// EtherType of the encapsulated frame.
    pub protocol_type: WireValue<u16>,
    /// 24-bit virtual network identifier.
    pub vni: u32,
    /// Reserved byte after the VNI.
    pub reserved2: u8,
    /// Verbatim option TLV bytes; the wire length field is derived.
    pub options: Bytes,
}

impl Default for Geneve {
    fn default() -> Self {
        Self {
            version: 0,
            control: false,
            critical: false,
            reserved1: 0,
            protocol_type: WireValue::Auto,
            vni: 0,
            reserved2: 0,
            options: Bytes::new(),
        }
    }
}

reflective_layer! {
    fn geneve_schema() => { protocol: protocol("geneve"), name: "GENEVE" }
    impl Geneve {
        "version" => { kind: Unsigned, derived: false, required: false, description: "2-bit GENEVE version; only version 0 is defined", reflect_bounded: version, 3_u64, layout: (0, 1) },
        "control" => { kind: Bool, derived: false, required: false, description: "Control-packet O bit", reflect: control, layout: (1, 2) },
        "critical" => { kind: Bool, derived: false, required: false, description: "Critical-options-present C bit", reflect: critical, layout: (1, 2) },
        "reserved1" => { kind: Unsigned, derived: false, required: false, description: "Reserved 6 bits after the O and C bits", reflect_bounded: reserved1, 0x3f_u64, layout: (1, 2) },
        "protocol_type" => { kind: Unsigned, derived: true, required: false, description: "EtherType of the encapsulated frame", reflect: protocol_type, layout: (2, 4) },
        "vni" => { kind: Unsigned, derived: false, required: true, description: "24-bit virtual network identifier", reflect_bounded: vni, VNI_MAX, layout: (4, 7) },
        "reserved2" => { kind: Unsigned, derived: false, required: false, description: "Reserved byte after the VNI", reflect: reserved2, layout: (7, 8) },
        "options" => { kind: Bytes, derived: false, required: false, description: "Verbatim GENEVE option TLV bytes", reflect: options, layout: (GENEVE_BASE_LEN, options_end) },
    }
    layout pub(crate) fn geneve_layout(options_end: usize);
}

/// What a well-formed option chain declares: whether any option carries the
/// critical bit, and whether any option header sets its three reserved bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OptionChain {
    critical: bool,
    reserved_bits: bool,
}

/// `None` when the bytes do not parse as an exact option chain.
fn parse_option_chain(options: &[u8]) -> Option<OptionChain> {
    let mut chain = OptionChain {
        critical: false,
        reserved_bits: false,
    };
    let mut cursor = 0_usize;
    while cursor < options.len() {
        if options.len() - cursor < OPTION_HEADER_LEN {
            return None;
        }
        chain.critical |= options[cursor + 2] & CRITICAL_OPTION_FLAG != 0;
        chain.reserved_bits |= options[cursor + 3] & 0xe0 != 0;
        let data_len = usize::from(options[cursor + 3] & 0x1f) * 4;
        cursor += OPTION_HEADER_LEN + data_len;
        if cursor > options.len() {
            return None;
        }
    }
    Some(chain)
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GeneveCodec;

impl LayerCodec for GeneveCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("geneve")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = layer
            .as_any()
            .downcast_ref::<Geneve>()
            .ok_or_else(|| wrong_layer("geneve", layer))?;
        let (header_len, mut diagnostics) = validate_geneve(layer, context)?;
        validate_auto_raw_discriminator(
            "geneve",
            "protocol_type",
            &layer.protocol_type,
            context,
            &mut diagnostics,
        )?;
        let (protocol_type, materialized_protocol_type) = resolve_u16(
            "geneve",
            "protocol_type",
            &layer.protocol_type,
            expected_discriminator("geneve", context, 0_u16),
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "geneve",
            u64::from(protocol_type),
            context,
            &mut diagnostics,
        )?;

        let mut prefix = Vec::with_capacity(header_len);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the guard above rejects options longer than GENEVE_MAX_OPTIONS_LEN, so the \
                      word count fits the 6-bit option-length field"
        )]
        let option_words = (layer.options.len() / 4) as u8;
        prefix.push((layer.version << 6) | option_words);
        prefix.push(
            (u8::from(layer.control) << 7) | (u8::from(layer.critical) << 6) | layer.reserved1,
        );
        prefix.extend_from_slice(&protocol_type.to_be_bytes());
        prefix.extend_from_slice(&layer.vni.to_be_bytes()[1..]);
        prefix.push(layer.reserved2);
        prefix.extend_from_slice(&layer.options);

        let mut materialized = layer.clone();
        materialized.protocol_type = materialized_protocol_type;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: geneve_layout(header_len),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        if input.len() < GENEVE_BASE_LEN {
            return Err(truncated("geneve", GENEVE_BASE_LEN, input.len()));
        }
        let version = input[0] >> 6;
        if version != 0 {
            return Err(crate::codec::Error::Unsupported {
                protocol: protocol("geneve"),
                message: format!("GENEVE version {version} is not supported"),
            });
        }
        let options_len = usize::from(input[0] & 0x3f) * 4;
        let header_len = GENEVE_BASE_LEN + options_len;
        if input.len() < header_len {
            return Err(truncated("geneve", header_len, input.len()));
        }
        let control = input[1] & 0x80 != 0;
        let critical = input[1] & 0x40 != 0;
        let reserved1 = input[1] & 0x3f;
        let protocol_type = u16::from_be_bytes([input[2], input[3]]);
        let vni = u32::from_be_bytes([0, input[4], input[5], input[6]]);
        let reserved2 = input[7];
        let options = Bytes::copy_from_slice(&input[GENEVE_BASE_LEN..header_len]);

        let mut diagnostics = Vec::new();
        if reserved1 != 0 || reserved2 != 0 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.geneve_reserved",
                    "GENEVE reserved bits are non-zero",
                )
                .at_field("reserved1"),
            );
        }
        match parse_option_chain(&options) {
            None => diagnostics.push(
                Diagnostic::warning(
                    "decode.geneve_options",
                    "GENEVE option bytes do not parse as an exact TLV chain; preserved verbatim",
                )
                .at_field("options"),
            ),
            Some(chain) => {
                if chain.critical != critical {
                    diagnostics.push(
                        Diagnostic::warning(
                            "decode.geneve_critical",
                            "the C bit disagrees with the critical options present in the chain",
                        )
                        .at_field("critical"),
                    );
                }
                if chain.reserved_bits {
                    diagnostics.push(
                        Diagnostic::warning(
                            "decode.geneve_reserved",
                            "GENEVE option-header reserved bits are non-zero",
                        )
                        .at_field("options"),
                    );
                }
            }
        }

        let layer = Geneve {
            version,
            control,
            critical,
            reserved1,
            protocol_type: WireValue::Exact(protocol_type),
            vni,
            reserved2,
            options,
        };
        let payload_len = input.len() - header_len;
        Ok(DecodedLayerValue {
            fields: geneve_layout(header_len),
            layer: Box::new(layer),
            consumed: header_len,
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Geneve::default(), fields)
    }
}

fn validate_geneve(
    layer: &Geneve,
    context: &LayerEncodeContext<'_>,
) -> Result<(usize, Vec<Diagnostic>), crate::codec::Error> {
    let header_len = GENEVE_BASE_LEN
        .checked_add(layer.options.len())
        .ok_or_else(|| invalid("geneve", "option length overflow"))?;
    ensure_encode_budget("geneve", header_len, context)?;
    if layer.version > 3 || layer.reserved1 > 0x3f || layer.vni > VNI_MAX {
        return Err(invalid("geneve", "field exceeds its wire range"));
    }
    if !layer.options.len().is_multiple_of(4) || layer.options.len() > GENEVE_MAX_OPTIONS_LEN {
        return Err(invalid(
            "geneve",
            format!(
                "options must be a multiple of 4 bytes up to {GENEVE_MAX_OPTIONS_LEN}, got {}",
                layer.options.len()
            ),
        ));
    }
    let mut diagnostics = Vec::new();
    if layer.version != 0 {
        strict_or_diagnostic(
            "geneve",
            "build.geneve_version",
            "version",
            "RFC 8926 defines only GENEVE version 0",
            context,
            &mut diagnostics,
        )?;
    }
    if layer.reserved1 != 0 || layer.reserved2 != 0 {
        strict_or_diagnostic(
            "geneve",
            "build.geneve_reserved",
            "reserved1",
            "GENEVE reserved fields must be zero on transmission",
            context,
            &mut diagnostics,
        )?;
    }
    match parse_option_chain(&layer.options) {
        None => strict_or_diagnostic(
            "geneve",
            "build.geneve_options",
            "options",
            "GENEVE option bytes do not parse as an exact TLV chain",
            context,
            &mut diagnostics,
        )?,
        Some(chain) => validate_option_chain(layer, chain, context, &mut diagnostics)?,
    }
    Ok((header_len, diagnostics))
}

fn validate_option_chain(
    layer: &Geneve,
    chain: OptionChain,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), crate::codec::Error> {
    if chain.critical != layer.critical {
        strict_or_diagnostic(
            "geneve",
            "build.geneve_critical",
            "critical",
            "the C bit must be set exactly when a critical option is present",
            context,
            diagnostics,
        )?;
    }
    if chain.reserved_bits {
        strict_or_diagnostic(
            "geneve",
            "build.geneve_reserved",
            "options",
            "GENEVE option-header reserved bits must be zero on transmission",
            context,
            diagnostics,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Packet;

    fn encode(
        layer: &Geneve,
        mode: crate::build::Mode,
        remaining_packet_bytes: usize,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry().expect("built-in registry");
        let packet = Packet::new();
        let build_context = crate::build::Context::default();
        let context = LayerEncodeContext {
            packet: &packet,
            index: 0,
            build_context: &build_context,
            mode,
            registry: &registry,
            child: None,
            remaining_packet_bytes,
        };
        GeneveCodec.encode(layer, &[], &context)
    }

    fn decode(input: &[u8]) -> Result<DecodedLayerValue, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry().expect("built-in registry");
        let context = LayerDecodeContext {
            registry: &registry,
            layer_index: 0,
            absolute_offset: 0,
            verify_checksums: true,
            allow_trailing_padding: false,
            network: None,
            discriminator: None,
        };
        GeneveCodec.decode(input, &context)
    }

    fn decode_error(input: &[u8]) -> crate::codec::Error {
        match decode(input) {
            Ok(_) => panic!("GENEVE vector unexpectedly decoded: {input:02x?}"),
            Err(error) => error,
        }
    }

    fn encode_error(layer: &Geneve) -> crate::codec::Error {
        match encode(layer, crate::build::Mode::Strict, usize::MAX) {
            Ok(_) => panic!("invalid GENEVE layer unexpectedly encoded: {layer:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn critical_option_chain_has_an_exact_wire_image_and_layout() {
        let options = Bytes::from_static(&[0x01, 0x02, 0x83, 0x01, 0xde, 0xad, 0xbe, 0xef]);
        let layer = Geneve {
            control: true,
            critical: true,
            protocol_type: WireValue::Exact(0x1234),
            vni: 0xab_cdef,
            options: options.clone(),
            ..Geneve::default()
        };

        let encoded = encode(&layer, crate::build::Mode::Strict, 16).unwrap();
        assert_eq!(
            encoded.prefix,
            [
                0x02, 0xc0, 0x12, 0x34, 0xab, 0xcd, 0xef, 0x00, 0x01, 0x02, 0x83, 0x01, 0xde, 0xad,
                0xbe, 0xef,
            ]
        );
        assert!(encoded.diagnostics.is_empty());
        assert_eq!(
            encoded
                .fields
                .iter()
                .find(|field| field.name == "options")
                .map(|field| field.range),
            Some(crate::layout::ByteRange::new(8, 16))
        );

        let decoded = decode(&encoded.prefix).unwrap();
        assert_eq!(decoded.consumed, 16);
        assert_eq!(decoded.payload_len, 0);
        assert!(decoded.stop);
        assert_eq!(decoded.next, [Discriminator(0x1234)]);
        assert!(decoded.diagnostics.is_empty());
        assert_eq!(
            decoded.layer.as_any().downcast_ref::<Geneve>(),
            Some(&layer)
        );
    }

    #[test]
    fn decoder_rejects_truncation_and_unknown_versions_before_reading_options() {
        assert!(matches!(
            decode_error(&[0; 7]),
            crate::codec::Error::Truncated {
                needed: 8,
                available: 7,
                ..
            }
        ));

        let mut unsupported = [0_u8; 8];
        unsupported[0] = 0x40;
        assert!(matches!(
            decode_error(&unsupported),
            crate::codec::Error::Unsupported { .. }
        ));

        let mut truncated_options = [0_u8; 8];
        truncated_options[0] = 1;
        assert!(matches!(
            decode_error(&truncated_options),
            crate::codec::Error::Truncated {
                needed: 12,
                available: 8,
                ..
            }
        ));
    }

    #[test]
    fn decoder_preserves_noncanonical_options_and_reports_each_wire_inconsistency() {
        let malformed_options = [0x01, 0x41, 0x12, 0x34, 0x00, 0x00, 0x01, 0x02, 0, 0, 0, 1];
        let decoded = decode(&malformed_options).unwrap();
        assert_eq!(
            decoded
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            ["decode.geneve_reserved", "decode.geneve_options"]
        );
        assert_eq!(
            decoded
                .layer
                .as_any()
                .downcast_ref::<Geneve>()
                .expect("typed GENEVE")
                .options,
            Bytes::from_static(&[0, 0, 0, 1])
        );

        let option_mismatch = [0x01, 0x00, 0x12, 0x34, 0, 0, 1, 0, 0, 0, 0x80, 0xe0];
        let decoded = decode(&option_mismatch).unwrap();
        assert_eq!(
            decoded
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            ["decode.geneve_critical", "decode.geneve_reserved"]
        );
    }

    #[test]
    fn encoder_enforces_field_option_and_packet_size_bounds_atomically() {
        let cases = [
            (
                Geneve {
                    version: 4,
                    ..Geneve::default()
                },
                "field exceeds its wire range",
            ),
            (
                Geneve {
                    vni: VNI_MAX + 1,
                    ..Geneve::default()
                },
                "field exceeds its wire range",
            ),
            (
                Geneve {
                    options: Bytes::from_static(&[0, 1, 2]),
                    ..Geneve::default()
                },
                "multiple of 4 bytes",
            ),
            (
                Geneve {
                    options: Bytes::from(vec![0; GENEVE_MAX_OPTIONS_LEN + 4]),
                    ..Geneve::default()
                },
                "multiple of 4 bytes up to",
            ),
            (
                Geneve {
                    options: Bytes::from_static(&[0, 0, 0, 1]),
                    ..Geneve::default()
                },
                "do not parse as an exact TLV chain",
            ),
            (
                Geneve {
                    options: Bytes::from_static(&[0, 0, 0x80, 0]),
                    ..Geneve::default()
                },
                "C bit must be set",
            ),
            (
                Geneve {
                    options: Bytes::from_static(&[0, 0, 0, 0xe0]),
                    ..Geneve::default()
                },
                "reserved bits must be zero",
            ),
        ];

        for (layer, expected) in cases {
            let error = encode_error(&layer);
            assert!(error.to_string().contains(expected), "{layer:?}: {error}");
        }

        let error = match encode(&Geneve::default(), crate::build::Mode::Strict, 7) {
            Ok(_) => panic!("undersized packet budget unexpectedly encoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("only 7 remain"));
    }

    #[test]
    fn permissive_mode_preserves_noncanonical_fields_with_actionable_diagnostics() {
        let layer = Geneve {
            version: 1,
            reserved1: 1,
            reserved2: 2,
            options: Bytes::from_static(&[0, 0, 0, 1]),
            ..Geneve::default()
        };
        let encoded = encode(&layer, crate::build::Mode::Permissive, 12).unwrap();

        assert_eq!(encoded.prefix.len(), 12);
        assert_eq!(
            encoded
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>(),
            [
                "build.geneve_version",
                "build.geneve_reserved",
                "build.geneve_options",
            ]
        );
    }
}
