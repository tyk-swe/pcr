// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::FieldValue,
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ensure_encode_budget, invalid, make_layer, out_of_range, protocol, strict_or_diagnostic,
    truncated, wrong_layer, wrong_type,
};

const MPLS_LEN: usize = 4;
const LABEL_MAX: u32 = 0x000f_ffff;

/// Discriminator for a continuing label stack entry (bottom-of-stack clear).
pub(crate) const MPLS_NEXT_LABEL: u64 = 0;
/// Discriminator for an opaque bottom-of-stack payload; also the rebuild slot
/// for a Raw child, since a pseudowire payload has no protocol field at all.
pub(crate) const MPLS_BOTTOM_RAW: u64 = 1;
/// The bottom-of-stack payload has no protocol field, so the decoder sniffs
/// the leading version nibble and offers it in a synthetic discriminator space
/// that cannot collide with the label-stack slots above.
pub(crate) const MPLS_BOTTOM_VERSION_BASE: u64 = 0x100;

/// One MPLS label stack entry (RFC 3032).
///
/// A cleared `bottom_of_stack` chains another `mpls` entry; a set one carries
/// the payload, whose IP version is sniffed from its first nibble because the
/// label stack has no protocol field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mpls {
    /// 20-bit MPLS label.
    pub label: u32,
    /// 3-bit traffic class, historically the EXP bits.
    pub traffic_class: u8,
    /// The S bit: this entry is the bottom of the label stack.
    pub bottom_of_stack: bool,
    /// Time to live.
    pub ttl: u8,
}

impl Default for Mpls {
    fn default() -> Self {
        Self {
            label: 0,
            traffic_class: 0,
            bottom_of_stack: true,
            ttl: 64,
        }
    }
}

reflective_layer! {
    fn mpls_schema() => { protocol: protocol("mpls"), name: "MPLS" }
    impl Mpls {
        "label" => { kind: Unsigned, derived: false, required: true, description: "20-bit MPLS label", get |layer| Some(FieldValue::from(layer.label)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.label = u32::try_from(value).ok().filter(|value| *value <= LABEL_MAX).ok_or_else(|| out_of_range(mpls_schema(), name))?; Ok(()) }, _ => Err(wrong_type(mpls_schema(), name, "unsigned")) }, layout: (0, 3) },
        "traffic_class" => { kind: Unsigned, derived: false, required: false, description: "3-bit traffic class, historically the EXP bits", get |layer| Some(reflect_get(&layer.traffic_class)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.traffic_class = u8::try_from(value).ok().filter(|value| *value <= 7).ok_or_else(|| out_of_range(mpls_schema(), name))?; Ok(()) }, _ => Err(wrong_type(mpls_schema(), name, "unsigned")) }, layout: (2, 3) },
        "bottom_of_stack" => { kind: Bool, derived: false, required: false, description: "S bit: this entry is the bottom of the label stack", get |layer| Some(reflect_get(&layer.bottom_of_stack)), set |layer, value, name| reflect_set(&mut layer.bottom_of_stack, mpls_schema(), name, value), layout: (2, 3) },
        "ttl" => { kind: Unsigned, derived: false, required: false, description: "Time to live", get |layer| Some(reflect_get(&layer.ttl)), set |layer, value, name| reflect_set(&mut layer.ttl, mpls_schema(), name, value), layout: (3, 4) }
    }
    layout pub(crate) fn mpls_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MplsCodec;

impl LayerCodec for MplsCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("mpls")
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
            .downcast_ref::<Mpls>()
            .ok_or_else(|| wrong_layer("mpls", layer))?;
        ensure_encode_budget("mpls", MPLS_LEN, context)?;
        if layer.label > LABEL_MAX || layer.traffic_class > 7 {
            return Err(invalid("mpls", "field exceeds its wire range"));
        }

        let mut diagnostics = Vec::new();
        // The S bit is the only thing that tells a dissector whether the next
        // bytes are another label entry or the payload, so it must agree with
        // what actually follows: another entry clears it, and anything else —
        // including nothing at all — ends the stack. A malformed child is a
        // dissected truncated stack, which must always rebuild.
        let expected_bottom = match context.child.map(|child| child.protocol_id().as_str()) {
            Some("mpls") => Some(false),
            Some("malformed") => None,
            _ => Some(true),
        };
        if let Some(expected_bottom) = expected_bottom
            && layer.bottom_of_stack != expected_bottom
        {
            strict_or_diagnostic(
                "mpls",
                "build.mpls_bottom",
                "bottom_of_stack",
                if expected_bottom {
                    "the S bit must be set on the last entry of the stack"
                } else {
                    "the S bit must be clear when another label entry follows"
                },
                context,
                &mut diagnostics,
            )?;
        }

        let word = (layer.label << 12)
            | (u32::from(layer.traffic_class) << 9)
            | (u32::from(layer.bottom_of_stack) << 8)
            | u32::from(layer.ttl);
        Ok(EncodedLayer {
            prefix: word.to_be_bytes().to_vec(),
            suffix: Vec::new(),
            materialized: Box::new(layer.clone()),
            fields: mpls_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < MPLS_LEN {
            return Err(truncated("mpls", MPLS_LEN, input.len()));
        }
        let word = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        let layer = Mpls {
            label: word >> 12,
            traffic_class: ((word >> 9) & 0x7) as u8,
            bottom_of_stack: word & 0x100 != 0,
            ttl: (word & 0xff) as u8,
        };
        let payload_len = input.len() - MPLS_LEN;
        let next = if !layer.bottom_of_stack {
            // Advertised even with no bytes left, so a stack truncated before
            // its bottom entry surfaces as a missing required child rather
            // than dissecting as complete.
            vec![Discriminator(MPLS_NEXT_LABEL)]
        } else if payload_len == 0 {
            Vec::new()
        } else {
            vec![
                Discriminator(MPLS_BOTTOM_VERSION_BASE + u64::from(input[MPLS_LEN] >> 4)),
                Discriminator(MPLS_BOTTOM_RAW),
            ]
        };
        Ok(DecodedLayerValue {
            fields: mpls_layout(),
            layer: Box::new(layer),
            consumed: MPLS_LEN,
            payload_offset: MPLS_LEN,
            payload_len,
            next,
            diagnostics: Vec::new(),
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Mpls::default(), fields)
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
    fn decode_reads_the_entry_and_offers_version_sniffed_bottom_children() {
        let registry = ProtocolRegistry::default();

        let continuing = MplsCodec
            .decode(&[0x00, 0x01, 0x44, 0xfe, 0xaa], &decode_context(&registry))
            .unwrap();
        let mpls = continuing.layer.as_any().downcast_ref::<Mpls>().unwrap();
        assert_eq!(mpls.label, 20);
        assert_eq!(mpls.traffic_class, 2);
        assert!(!mpls.bottom_of_stack);
        assert_eq!(mpls.ttl, 0xfe);
        assert_eq!(continuing.next, vec![Discriminator(MPLS_NEXT_LABEL)]);

        let bottom = MplsCodec
            .decode(&[0x00, 0x01, 0x41, 0x40, 0x45], &decode_context(&registry))
            .unwrap();
        assert_eq!(
            bottom.next,
            vec![
                Discriminator(MPLS_BOTTOM_VERSION_BASE + 4),
                Discriminator(MPLS_BOTTOM_RAW),
            ]
        );

        // A control-word pseudowire payload starts with nibble zero, which
        // must never alias the label-continuation discriminator.
        let pseudowire = MplsCodec
            .decode(&[0x00, 0x01, 0x41, 0x40, 0x00], &decode_context(&registry))
            .unwrap();
        assert_eq!(
            pseudowire.next,
            vec![
                Discriminator(MPLS_BOTTOM_VERSION_BASE),
                Discriminator(MPLS_BOTTOM_RAW),
            ]
        );

        assert!(matches!(
            MplsCodec.decode(&[0, 1, 2], &decode_context(&registry)),
            Err(CodecError::Truncated { .. })
        ));
    }
}
