// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use packetcraftr_packet::{
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
    ensure_encode_budget, expected_discriminator, invalid, make_layer, out_of_range, protocol,
    resolve_u16, strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_raw_child_discriminator, wrong_layer, wrong_type,
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
        "version" => { kind: Unsigned, derived: false, required: false, description: "2-bit GENEVE version; only version 0 is defined", get |layer| Some(reflect_get(&layer.version)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.version = u8::try_from(value).ok().filter(|value| *value <= 3).ok_or_else(|| out_of_range(geneve_schema(), name))?; Ok(()) }, _ => Err(wrong_type(geneve_schema(), name, "unsigned")) }, layout: (0, 1) },
        "control" => { kind: Bool, derived: false, required: false, description: "Control-packet O bit", get |layer| Some(reflect_get(&layer.control)), set |layer, value, name| reflect_set(&mut layer.control, geneve_schema(), name, value), layout: (1, 2) },
        "critical" => { kind: Bool, derived: false, required: false, description: "Critical-options-present C bit", get |layer| Some(reflect_get(&layer.critical)), set |layer, value, name| reflect_set(&mut layer.critical, geneve_schema(), name, value), layout: (1, 2) },
        "reserved1" => { kind: Unsigned, derived: false, required: false, description: "Reserved 6 bits after the O and C bits", get |layer| Some(reflect_get(&layer.reserved1)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.reserved1 = u8::try_from(value).ok().filter(|value| *value <= 0x3f).ok_or_else(|| out_of_range(geneve_schema(), name))?; Ok(()) }, _ => Err(wrong_type(geneve_schema(), name, "unsigned")) }, layout: (1, 2) },
        "protocol_type" => { kind: Unsigned, derived: true, required: false, description: "EtherType of the encapsulated frame", get |layer| Some(reflect_get(&layer.protocol_type)), set |layer, value, name| reflect_set(&mut layer.protocol_type, geneve_schema(), name, value), layout: (2, 4) },
        "vni" => { kind: Unsigned, derived: false, required: true, description: "24-bit virtual network identifier", get |layer| Some(FieldValue::from(layer.vni)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.vni = u32::try_from(value).ok().filter(|value| *value <= VNI_MAX).ok_or_else(|| out_of_range(geneve_schema(), name))?; Ok(()) }, _ => Err(wrong_type(geneve_schema(), name, "unsigned")) }, layout: (4, 7) },
        "reserved2" => { kind: Unsigned, derived: false, required: false, description: "Reserved byte after the VNI", get |layer| Some(reflect_get(&layer.reserved2)), set |layer, value, name| reflect_set(&mut layer.reserved2, geneve_schema(), name, value), layout: (7, 8) },
        "options" => { kind: Bytes, derived: false, required: false, description: "Verbatim GENEVE option TLV bytes", get |layer| Some(reflect_get(&layer.options)), set |layer, value, name| reflect_set(&mut layer.options, geneve_schema(), name, value), layout: (GENEVE_BASE_LEN, options_end) },
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
    fn protocol_id(&self) -> ProtocolId {
        protocol("geneve")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Geneve>()
            .ok_or_else(|| wrong_layer("geneve", layer))?;
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
            Some(chain) => {
                if chain.critical != layer.critical {
                    strict_or_diagnostic(
                        "geneve",
                        "build.geneve_critical",
                        "critical",
                        "the C bit must be set exactly when a critical option is present",
                        context,
                        &mut diagnostics,
                    )?;
                }
                if chain.reserved_bits {
                    strict_or_diagnostic(
                        "geneve",
                        "build.geneve_reserved",
                        "options",
                        "GENEVE option-header reserved bits must be zero on transmission",
                        context,
                        &mut diagnostics,
                    )?;
                }
            }
        }
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
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < GENEVE_BASE_LEN {
            return Err(truncated("geneve", GENEVE_BASE_LEN, input.len()));
        }
        let version = input[0] >> 6;
        if version != 0 {
            return Err(CodecError::Unsupported {
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
        make_layer(Geneve::default(), fields)
    }
}
