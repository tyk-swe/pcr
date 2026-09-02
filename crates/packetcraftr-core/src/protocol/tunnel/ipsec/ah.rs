// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    protocol::BuiltinProtocol,
    registry::Discriminator,
};

use crate::protocol::common::{
    ValueExpectation, ensure_encode_budget, expected_discriminator, invalid, make_layer, protocol,
    resolve_u8, strict_or_diagnostic, truncated, typed_layer, validate_auto_raw_discriminator,
    validate_raw_child_discriminator,
};

const NAME: &str = BuiltinProtocol::Ah.as_str();

const AH_FIXED_LEN: usize = 12;

/// Whether a protocol behind AH belongs to the other address family. The
/// shared `ah` registry entry binds children of both families, so the codec
/// itself keeps ICMPv4 out of IPv6 chains and the IPv6 repertoire out of
/// IPv4 ones.
fn ah_family_mismatch(under_ipv6: Option<bool>, child: Option<BuiltinProtocol>) -> bool {
    let Some(child) = child else {
        return false;
    };
    match under_ipv6 {
        // AH is itself an IPv6 extension header but belongs to both families,
        // so the IPv6-only repertoire is every other extension plus ICMPv6.
        Some(false) => {
            child == BuiltinProtocol::Icmpv6
                || (child.is_ipv6_extension() && child != BuiltinProtocol::Ah)
        }
        Some(true) => matches!(child, BuiltinProtocol::Icmpv4 | BuiltinProtocol::Igmp),
        None => false,
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
    fn ah_schema() => { protocol: protocol(NAME), name: "AH" }
    impl Ah {
        "next_header" => { kind: Unsigned, derived: true, required: false, description: "Protocol number of the authenticated payload", reflect: next_header, layout: (0, 1) },
        "payload_length" => { kind: Unsigned, derived: true, required: false, description: "Header length in 4-byte units minus two", reflect: payload_length, layout: (1, 2) },
        "reserved" => { kind: Unsigned, derived: false, required: false, description: "Reserved 16 bits", reflect: reserved, layout: (2, 4) },
        "spi" => { kind: Unsigned, derived: false, required: true, description: "Security parameters index", reflect: spi, layout: (4, 8) },
        "sequence" => { kind: Unsigned, derived: false, required: false, description: "Anti-replay sequence number", reflect: sequence, layout: (8, 12) },
        "icv" => { kind: Bytes, derived: false, required: false, description: "Integrity check value, a multiple of 4 bytes", reflect: icv, layout: (AH_FIXED_LEN, header_len) },
    }
    layout pub(crate) fn ah_layout(header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AhCodec;

impl LayerCodec for AhCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &ah_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Ah>(NAME, layer)?;
        let header_len = AH_FIXED_LEN
            .checked_add(layer.icv.len())
            .ok_or_else(|| invalid(NAME, "ICV length overflow"))?;
        ensure_encode_budget(NAME, header_len, context)?;
        if !layer.icv.len().is_multiple_of(4) || header_len > (0xff + 2) * 4 {
            return Err(invalid(
                NAME,
                "the ICV must be a multiple of 4 bytes within the length field's range",
            ));
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the guard above rejects header_len > (0xff + 2) * 4, so the word count \
                      minus two fits the 8-bit payload-length field"
        )]
        let expected_payload_length = (header_len / 4).saturating_sub(2) as u8;

        let (under_ipv6, mut diagnostics) = validate_context(layer, header_len, context)?;
        validate_auto_raw_discriminator(
            NAME,
            "next_header",
            &layer.next_header,
            context,
            &mut diagnostics,
        )?;
        let (next_header, materialized_next_header) = resolve_u8(
            NAME,
            "next_header",
            &layer.next_header,
            expected_discriminator(NAME, context, 59_u8, &layer.next_header),
            context.mode,
            &mut diagnostics,
        )?;
        // A discriminator whose registered child belongs to the other
        // address family selects nothing in this one — decode keeps such
        // payloads opaque — so a raw child is the faithful rebuild there.
        let selects_cross_family = context
            .registry
            .child_for(NAME, Discriminator(u64::from(next_header)))
            .is_some_and(|selected| {
                ah_family_mismatch(under_ipv6, BuiltinProtocol::from_id(selected))
            });
        if !selects_cross_family {
            validate_raw_child_discriminator(
                NAME,
                u64::from(next_header),
                context,
                &mut diagnostics,
            )?;
        }
        let (payload_length, materialized_payload_length) = resolve_u8(
            NAME,
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
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(ah_layout(header_len))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(fixed) = input.first_chunk::<AH_FIXED_LEN>() else {
            return Err(truncated(NAME, AH_FIXED_LEN, input.len()));
        };
        let payload_length = fixed[1];
        let header_len = usize::from(payload_length)
            .saturating_add(2)
            .saturating_mul(4);
        if header_len < AH_FIXED_LEN {
            return Err(invalid(
                NAME,
                format!("payload length {payload_length} is below the fixed header"),
            ));
        }
        let Some(icv) = input.get(AH_FIXED_LEN..header_len) else {
            return Err(truncated(NAME, header_len, input.len()));
        };
        let next_header = fixed[0];
        let reserved = u16::from_be_bytes([fixed[2], fixed[3]]);
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
            .child_for(NAME, Discriminator(u64::from(next_header)))
            .is_some_and(|selected| {
                ah_family_mismatch(under_ipv6, BuiltinProtocol::from_id(selected))
            });
        if cross_family {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.ah_family",
                    "the next header does not belong to the enclosing address family",
                )
                .at_field("next_header"),
            );
        }
        let payload_len = input.len().saturating_sub(header_len);
        Ok(DecodedLayer {
            fields: ah_layout(header_len),
            layer: Box::new(Ah {
                next_header: WireValue::Exact(next_header),
                payload_length: WireValue::Exact(payload_length),
                reserved,
                spi: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
                sequence: u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]),
                icv: Bytes::copy_from_slice(icv),
            }),
            consumed: header_len,
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Ah::default(), fields)
    }
}

fn validate_context(
    layer: &Ah,
    header_len: usize,
    context: &LayerEncodeContext<'_>,
) -> Result<(Option<bool>, Vec<Diagnostic>), crate::codec::Error> {
    let mut diagnostics = Vec::new();
    if layer.spi == 0 {
        strict_or_diagnostic(
            NAME,
            "build.ah_spi",
            "spi",
            "SPI zero is reserved and must not appear on the wire",
            context,
            &mut diagnostics,
        )?;
    }
    if layer.reserved != 0 {
        strict_or_diagnostic(
            NAME,
            "build.ah_reserved",
            "reserved",
            "the AH reserved field must be zero on transmission",
            context,
            &mut diagnostics,
        )?;
    }
    let under_ipv6 =
        context.packet.iter().take(context.index).rev().find_map(
            |parent| match BuiltinProtocol::of(parent) {
                Some(BuiltinProtocol::Ipv4) => Some(false),
                Some(BuiltinProtocol::Ah) => None,
                Some(parent) if parent == BuiltinProtocol::Ipv6 || parent.is_ipv6_extension() => {
                    Some(true)
                }
                _ => None,
            },
        );
    if under_ipv6 == Some(true) && !header_len.is_multiple_of(8) {
        strict_or_diagnostic(
            NAME,
            "build.ah_alignment",
            "icv",
            "an IPv6 AH header must be a multiple of 8 octets",
            context,
            &mut diagnostics,
        )?;
    }
    if let Some(child) = context.child
        && ah_family_mismatch(under_ipv6, BuiltinProtocol::of(child))
    {
        strict_or_diagnostic(
            NAME,
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
    Ok((under_ipv6, diagnostics))
}
