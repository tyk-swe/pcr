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
    semantics::BuiltinProtocol,
};

use super::super::common::{
    ValueExpectation, ensure_encode_budget, expected_discriminator_for_value, invalid, make_layer,
    payload_without_padding, protocol, resolve_u8, strict_or_diagnostic, truncated,
    validate_auto_raw_discriminator, validate_raw_child_discriminator, wrong_layer,
};

const ESP_LEN: usize = 8;
const AH_FIXED_LEN: usize = 12;

/// Whether a protocol behind AH belongs to the other address family. The
/// shared `ah` registry entry binds children of both families, so the codec
/// itself keeps ICMPv4 out of IPv6 chains and the IPv6 repertoire out of
/// IPv4 ones.
fn ah_family_mismatch(under_ipv6: Option<bool>, child: &str) -> bool {
    match under_ipv6 {
        Some(true) => matches!(child, "icmpv4" | "igmp"),
        Some(false) => matches!(
            child,
            "icmpv6"
                | "ipv6_hop_by_hop"
                | "ipv6_destination_options"
                | "ipv6_fragment"
                | "ipv6_srh"
        ),
        None => false,
    }
}

/// IPsec ESP header (RFC 4303), IP protocol 50.
///
/// Everything after the sequence number is ciphertext — including the
/// trailer and ICV — so the payload is deliberately opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Esp {
    /// Security parameters index.
    pub spi: u32,
    /// Anti-replay sequence number.
    pub sequence: u32,
}

impl Default for Esp {
    fn default() -> Self {
        Self {
            // The first SPI outside the reserved ranges: zero must never
            // appear on the wire and 1-255 are held by IANA.
            spi: 256,
            sequence: 0,
        }
    }
}

reflective_layer! {
    fn esp_schema() => { protocol: protocol("esp"), name: "ESP" }
    impl Esp {
        "spi" => { kind: Unsigned, derived: false, required: true, description: "Security parameters index", get |layer| Some(reflect_get(&layer.spi)), set |layer, value, name| reflect_set(&mut layer.spi, esp_schema(), name, value), layout: (0, 4) },
        "sequence" => { kind: Unsigned, derived: false, required: false, description: "Anti-replay sequence number", get |layer| Some(reflect_get(&layer.sequence)), set |layer, value, name| reflect_set(&mut layer.sequence, esp_schema(), name, value), layout: (4, 8) }
    }
    layout pub(crate) fn esp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EspCodec;

impl LayerCodec for EspCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("esp")
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
            .downcast_ref::<Esp>()
            .ok_or_else(|| wrong_layer("esp", layer))?;
        ensure_encode_budget("esp", ESP_LEN, context)?;
        let mut diagnostics = Vec::new();
        // The ciphertext always ends in the two-byte Pad Length / Next
        // Header trailer, so a shorter payload cannot be a complete packet.
        if payload_without_padding("esp", payload, context)?.len() < 2 {
            strict_or_diagnostic(
                "esp",
                "build.esp_trailer",
                "spi",
                "the encrypted payload must include the two-byte ESP trailer",
                context,
                &mut diagnostics,
            )?;
        }
        if layer.spi == 0 {
            strict_or_diagnostic(
                "esp",
                "build.esp_spi",
                "spi",
                "SPI zero is reserved and must not appear on the wire",
                context,
                &mut diagnostics,
            )?;
        }
        // The payload is ciphertext: a typed child would serialize plaintext
        // protocol structure that dissection deliberately never recovers, so
        // the layer stack could not round-trip.
        if let Some(child) = context.child
            && !matches!(
                child.protocol_id().as_str(),
                "raw" | "padding" | "malformed"
            )
        {
            strict_or_diagnostic(
                "esp",
                "build.esp_ciphertext",
                "spi",
                format!(
                    "the ESP payload is ciphertext; carry the {} bytes as a raw layer",
                    child.protocol_id()
                ),
                context,
                &mut diagnostics,
            )?;
        }
        let mut prefix = Vec::with_capacity(ESP_LEN);
        prefix.extend_from_slice(&layer.spi.to_be_bytes());
        prefix.extend_from_slice(&layer.sequence.to_be_bytes());
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(layer.clone()),
            fields: esp_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < ESP_LEN {
            return Err(truncated("esp", ESP_LEN, input.len()));
        }
        let payload_len = input.len() - ESP_LEN;
        let mut diagnostics = Vec::new();
        if payload_len < 2 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.esp_trailer",
                    "the ciphertext is too short for the two-byte ESP trailer",
                )
                .at_field("sequence"),
            );
        }
        Ok(DecodedLayerValue {
            fields: esp_layout(),
            layer: Box::new(Esp {
                spi: u32::from_be_bytes([input[0], input[1], input[2], input[3]]),
                sequence: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
            }),
            consumed: ESP_LEN,
            payload_offset: ESP_LEN,
            payload_len,
            // Ciphertext: always the opaque child.
            next: vec![Discriminator(0)],
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Esp::default(), fields)
    }
}

/// IPsec Authentication Header (RFC 4302), IP protocol 51.
///
/// Unlike ESP it authenticates rather than encrypts, so the next-header
/// chain continues through it and the payload dissects normally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ah {
    /// Protocol number of the authenticated payload.
    pub next_header: WireValue<u8>,
    /// Header length in 4-byte units minus two; derived from the ICV.
    pub payload_length: WireValue<u8>,
    /// Reserved 16 bits.
    pub reserved: u16,
    /// Security parameters index.
    pub spi: u32,
    /// Anti-replay sequence number.
    pub sequence: u32,
    /// Integrity check value, a multiple of 4 bytes.
    pub icv: Bytes,
}

impl Default for Ah {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            payload_length: WireValue::Auto,
            reserved: 0,
            spi: 256,
            sequence: 0,
            // The mandatory-to-implement integrity algorithms truncate to 96
            // bits, so a placeholder ICV of that size keeps defaults aligned.
            icv: Bytes::from_static(&[0; 12]),
        }
    }
}

reflective_layer! {
    fn ah_schema() => { protocol: protocol("ah"), name: "AH" }
    impl Ah {
        "next_header" => { kind: Unsigned, derived: true, required: false, description: "Protocol number of the authenticated payload", get |layer| Some(reflect_get(&layer.next_header)), set |layer, value, name| reflect_set(&mut layer.next_header, ah_schema(), name, value), layout: (0, 1) },
        "payload_length" => { kind: Unsigned, derived: true, required: false, description: "Header length in 4-byte units minus two", get |layer| Some(reflect_get(&layer.payload_length)), set |layer, value, name| reflect_set(&mut layer.payload_length, ah_schema(), name, value), layout: (1, 2) },
        "reserved" => { kind: Unsigned, derived: false, required: false, description: "Reserved 16 bits", get |layer| Some(reflect_get(&layer.reserved)), set |layer, value, name| reflect_set(&mut layer.reserved, ah_schema(), name, value), layout: (2, 4) },
        "spi" => { kind: Unsigned, derived: false, required: true, description: "Security parameters index", get |layer| Some(reflect_get(&layer.spi)), set |layer, value, name| reflect_set(&mut layer.spi, ah_schema(), name, value), layout: (4, 8) },
        "sequence" => { kind: Unsigned, derived: false, required: false, description: "Anti-replay sequence number", get |layer| Some(reflect_get(&layer.sequence)), set |layer, value, name| reflect_set(&mut layer.sequence, ah_schema(), name, value), layout: (8, 12) },
        "icv" => { kind: Bytes, derived: false, required: false, description: "Integrity check value, a multiple of 4 bytes", get |layer| Some(reflect_get(&layer.icv)), set |layer, value, name| reflect_set(&mut layer.icv, ah_schema(), name, value), layout: (AH_FIXED_LEN, header_len) },
        normalize |layer| { layer.next_header.normalize(); layer.payload_length.normalize(); }
    }
    layout pub(crate) fn ah_layout(header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AhCodec;

impl LayerCodec for AhCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ah")
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
            .downcast_ref::<Ah>()
            .ok_or_else(|| wrong_layer("ah", layer))?;
        let header_len = AH_FIXED_LEN
            .checked_add(layer.icv.len())
            .ok_or_else(|| invalid("ah", "ICV length overflow"))?;
        ensure_encode_budget("ah", header_len, context)?;
        if !layer.icv.len().is_multiple_of(4) || header_len > (0xff + 2) * 4 {
            return Err(invalid(
                "ah",
                "the ICV must be a multiple of 4 bytes within the length field's range",
            ));
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the guard above rejects header_len > (0xff + 2) * 4, so the word count \
                      minus two fits the 8-bit payload-length field"
        )]
        let expected_payload_length = (header_len / 4 - 2) as u8;

        let mut diagnostics = Vec::new();
        if layer.spi == 0 {
            strict_or_diagnostic(
                "ah",
                "build.ah_spi",
                "spi",
                "SPI zero is reserved and must not appear on the wire",
                context,
                &mut diagnostics,
            )?;
        }
        if layer.reserved != 0 {
            strict_or_diagnostic(
                "ah",
                "build.ah_reserved",
                "reserved",
                "the AH reserved field must be zero on transmission",
                context,
                &mut diagnostics,
            )?;
        }
        // RFC 4302 aligns the header to its address family: 4 octets under
        // IPv4 and 8 under IPv6, the extension-header unit.
        let under_ipv6 = context
            .packet
            .iter()
            .take(context.index)
            .rev()
            .find_map(|parent| match BuiltinProtocol::of(parent) {
                Some(BuiltinProtocol::Ipv4) => Some(false),
                // A preceding AH takes its family from whatever encloses it.
                Some(BuiltinProtocol::Ah) => None,
                Some(parent) if parent == BuiltinProtocol::Ipv6 || parent.is_ipv6_extension() => {
                    Some(true)
                }
                _ => None,
            });
        if under_ipv6 == Some(true) && !header_len.is_multiple_of(8) {
            strict_or_diagnostic(
                "ah",
                "build.ah_alignment",
                "icv",
                "an IPv6 AH header must be a multiple of 8 octets",
                context,
                &mut diagnostics,
            )?;
        }
        if let Some(child) = context.child
            && ah_family_mismatch(under_ipv6, child.protocol_id().as_str())
        {
            strict_or_diagnostic(
                "ah",
                "build.ah_family",
                "next_header",
                format!(
                    "{} does not belong to the enclosing address family",
                    child.protocol_id()
                ),
                context,
                &mut diagnostics,
            )?;
        }
        validate_auto_raw_discriminator(
            "ah",
            "next_header",
            &layer.next_header,
            context,
            &mut diagnostics,
        )?;
        let (next_header, materialized_next_header) = resolve_u8(
            "ah",
            "next_header",
            &layer.next_header,
            expected_discriminator_for_value("ah", context, 59_u8, &layer.next_header),
            context.mode,
            &mut diagnostics,
        )?;
        // A discriminator whose registered child belongs to the other
        // address family selects nothing in this one — decode keeps such
        // payloads opaque — so a raw child is the faithful rebuild there.
        let selects_cross_family = context
            .registry
            .child_for("ah", Discriminator(u64::from(next_header)))
            .is_some_and(|selected| ah_family_mismatch(under_ipv6, selected.as_str()));
        if !selects_cross_family {
            validate_raw_child_discriminator(
                "ah",
                u64::from(next_header),
                context,
                &mut diagnostics,
            )?;
        }
        let (payload_length, materialized_payload_length) = resolve_u8(
            "ah",
            "payload_length",
            &layer.payload_length,
            ValueExpectation::Required(expected_payload_length),
            context.mode,
            &mut diagnostics,
        )?;

        let mut prefix = Vec::with_capacity(header_len);
        prefix.push(next_header);
        prefix.push(payload_length);
        prefix.extend_from_slice(&layer.reserved.to_be_bytes());
        prefix.extend_from_slice(&layer.spi.to_be_bytes());
        prefix.extend_from_slice(&layer.sequence.to_be_bytes());
        prefix.extend_from_slice(&layer.icv);
        let mut materialized = layer.clone();
        materialized.next_header = materialized_next_header;
        materialized.payload_length = materialized_payload_length;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: ah_layout(header_len),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < AH_FIXED_LEN {
            return Err(truncated("ah", AH_FIXED_LEN, input.len()));
        }
        let payload_length = input[1];
        let header_len = (usize::from(payload_length) + 2) * 4;
        if header_len < AH_FIXED_LEN {
            return Err(invalid(
                "ah",
                format!("payload length {payload_length} is below the fixed header"),
            ));
        }
        if input.len() < header_len {
            return Err(truncated("ah", header_len, input.len()));
        }
        let next_header = input[0];
        let reserved = u16::from_be_bytes([input[2], input[3]]);
        let mut diagnostics = Vec::new();
        if reserved != 0 {
            diagnostics.push(
                Diagnostic::warning("decode.ah_reserved", "the AH reserved field is non-zero")
                    .at_field("reserved"),
            );
        }
        let under_ipv6 = context.network.map(|network| network.source.is_ipv6());
        if under_ipv6 == Some(true) && !header_len.is_multiple_of(8) {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.ah_alignment",
                    "an IPv6 AH header must be a multiple of 8 octets",
                )
                .at_field("payload_length"),
            );
        }
        // A next_header naming the other family's repertoire never selects
        // that child; the payload stays opaque instead.
        let cross_family = context
            .registry
            .child_for("ah", Discriminator(u64::from(next_header)))
            .is_some_and(|selected| ah_family_mismatch(under_ipv6, selected.as_str()));
        if cross_family {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.ah_family",
                    "the next header does not belong to the enclosing address family",
                )
                .at_field("next_header"),
            );
        }
        let payload_len = input.len() - header_len;
        Ok(DecodedLayerValue {
            fields: ah_layout(header_len),
            layer: Box::new(Ah {
                next_header: WireValue::Exact(next_header),
                payload_length: WireValue::Exact(payload_length),
                reserved,
                spi: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                sequence: u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
                icv: Bytes::copy_from_slice(&input[AH_FIXED_LEN..header_len]),
            }),
            consumed: header_len,
            payload_offset: header_len,
            payload_len,
            next: if cross_family {
                Vec::new()
            } else {
                vec![Discriminator(u64::from(next_header))]
            },
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Ah::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_packet::registry::ProtocolRegistry;

    fn decode_context(registry: &ProtocolRegistry) -> LayerDecodeContext<'_> {
        LayerDecodeContext {
            registry,
            layer_index: 0,
            absolute_offset: 0,
            verify_checksums: false,
            allow_trailing_padding: false,
            network: None,
            discriminator: None,
        }
    }

    #[test]
    fn esp_reads_its_header_and_keeps_the_ciphertext_opaque() {
        let registry = ProtocolRegistry::default();
        let decoded = EspCodec
            .decode(
                &[0, 0, 0x30, 0x39, 0, 0, 0, 7, 0xde, 0xad],
                &decode_context(&registry),
            )
            .unwrap();
        let esp = decoded.layer.as_any().downcast_ref::<Esp>().unwrap();

        assert_eq!(esp.spi, 12345);
        assert_eq!(esp.sequence, 7);
        assert_eq!(decoded.payload_len, 2);
        assert_eq!(decoded.next, vec![Discriminator(0)]);

        assert!(matches!(
            EspCodec.decode(&[0; 7], &decode_context(&registry)),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn ah_gates_non_zero_reserved_bits_on_permissive_mode() {
        use packetcraftr_packet::{
            Packet,
            build::{BuildContext, BuildMode},
        };

        let ah = Ah {
            next_header: WireValue::Exact(59),
            reserved: 7,
            ..Ah::default()
        };
        let mut packet = Packet::new();
        packet.push(ah.clone());
        let registry = ProtocolRegistry::default();
        let build_context = BuildContext::default();
        let encode = |mode| {
            AhCodec.encode(
                &ah,
                &[],
                &LayerEncodeContext {
                    packet: &packet,
                    index: 0,
                    build_context: &build_context,
                    mode,
                    registry: &registry,
                    child: None,
                    remaining_packet_bytes: 64,
                },
            )
        };

        assert!(matches!(
            encode(BuildMode::Strict),
            Err(CodecError::Invalid { .. })
        ));
        let permissive = encode(BuildMode::Permissive).unwrap();
        assert!(
            permissive
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "build.ah_reserved")
        );

        let mut bytes = vec![59, 4, 0, 7, 0, 0, 0, 9, 0, 0, 0, 1];
        bytes.extend_from_slice(&[0; 12]);
        let decoded = AhCodec.decode(&bytes, &decode_context(&registry)).unwrap();
        assert_eq!(decoded.diagnostics[0].code, "decode.ah_reserved");
    }

    #[test]
    fn ah_reads_the_icv_from_its_length_field_and_continues_the_chain() {
        let registry = ProtocolRegistry::default();
        let mut bytes = vec![6, 4, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1];
        bytes.extend_from_slice(&[0xaa; 12]);
        bytes.extend_from_slice(&[0x02]);
        let decoded = AhCodec.decode(&bytes, &decode_context(&registry)).unwrap();
        let ah = decoded.layer.as_any().downcast_ref::<Ah>().unwrap();

        assert_eq!(ah.next_header, WireValue::Exact(6));
        assert_eq!(ah.spi, 9);
        assert_eq!(ah.icv.as_ref(), &[0xaa; 12]);
        assert_eq!(decoded.consumed, 24);
        assert_eq!(decoded.payload_len, 1);
        assert_eq!(decoded.next, vec![Discriminator(6)]);

        // The declared length must cover the fixed header and fit the input.
        assert!(matches!(
            AhCodec.decode(
                &[6, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1],
                &decode_context(&registry)
            ),
            Err(CodecError::Invalid { .. })
        ));
        assert!(matches!(
            AhCodec.decode(
                &[6, 9, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1],
                &decode_context(&registry)
            ),
            Err(CodecError::Truncated { .. })
        ));
    }
}
