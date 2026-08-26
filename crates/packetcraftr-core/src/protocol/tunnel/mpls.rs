// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ensure_encode_budget, invalid, make_layer, protocol, strict_or_diagnostic, truncated,
    wrong_layer,
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
        "label" => { kind: Unsigned, tier: Required, description: "20-bit MPLS label", reflect_bounded: label, LABEL_MAX, layout: (0, 3) },
        "traffic_class" => { kind: Unsigned, tier: Optional, default: "0", description: "3-bit traffic class, historically the EXP bits", reflect_bounded: traffic_class, 7_u64, layout: (2, 3) },
        "bottom_of_stack" => { kind: Bool, tier: Optional, default: "true", description: "S bit: this entry is the bottom of the label stack", reflect: bottom_of_stack, layout: (2, 3) },
        "ttl" => { kind: Unsigned, tier: Optional, default: "64", description: "Time to live", reflect: ttl, layout: (3, 4) }
    }
    layout pub(crate) fn mpls_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MplsCodec;

impl LayerCodec for MplsCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("mpls")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
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
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(header) = input.first_chunk::<MPLS_LEN>() else {
            return Err(truncated("mpls", MPLS_LEN, input.len()));
        };
        let word = u32::from_be_bytes(*header);
        let layer = Mpls {
            label: word >> 12,
            traffic_class: ((word >> 9) & 0x7) as u8,
            bottom_of_stack: word & 0x100 != 0,
            ttl: (word & 0xff) as u8,
        };
        let payload = input.get(MPLS_LEN..).unwrap_or_default();
        let payload_len = payload.len();
        let next = if !layer.bottom_of_stack {
            // Advertised even with no bytes left, so a stack truncated before
            // its bottom entry surfaces as a missing required child rather
            // than dissecting as complete.
            vec![Discriminator(MPLS_NEXT_LABEL)]
        } else if let Some(&first) = payload.first() {
            vec![
                Discriminator(MPLS_BOTTOM_VERSION_BASE.saturating_add(u64::from(first >> 4))),
                Discriminator(MPLS_BOTTOM_RAW),
            ]
        } else {
            Vec::new()
        };
        Ok(DecodedLayerValue {
            fields: mpls_layout(),
            layer: Box::new(layer),
            consumed: MPLS_LEN,
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Mpls::default(), fields)
    }
}
