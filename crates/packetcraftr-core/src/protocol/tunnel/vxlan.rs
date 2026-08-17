// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::{
    codec::{
        DecodedLayerValue, EncodedLayer, Error as CodecError, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Id as ProtocolId, Layer, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ensure_encode_budget, invalid, make_layer, protocol, strict_or_diagnostic, truncated,
    validate_raw_child_discriminator, wrong_layer,
};

const VXLAN_LEN: usize = 8;
/// The I flag: the VNI field is valid. RFC 7348 requires it set and every
/// other flag bit clear.
const VNI_VALID_FLAG: u8 = 0x08;
const VNI_MAX: u32 = 0x00ff_ffff;

/// VXLAN encapsulation header (RFC 7348).
///
/// The inner payload is always an Ethernet frame, so the codec advertises a
/// single child discriminator rather than carrying a protocol field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vxlan {
    /// Flag byte; RFC 7348 defines only the VNI-valid bit.
    pub flags: u8,
    /// 24-bit VXLAN network identifier.
    pub vni: u32,
    /// Reserved 24 bits between the flags and the VNI.
    pub reserved1: u32,
    /// Reserved byte after the VNI.
    pub reserved2: u8,
}

impl Default for Vxlan {
    fn default() -> Self {
        Self {
            flags: VNI_VALID_FLAG,
            vni: 0,
            reserved1: 0,
            reserved2: 0,
        }
    }
}

reflective_layer! {
    fn vxlan_schema() => { protocol: protocol("vxlan"), name: "VXLAN" }
    impl Vxlan {
        "flags" => { kind: Unsigned, derived: false, required: true, description: "VXLAN flag byte; only the VNI-valid bit 0x08 is defined", reflect: flags, layout: (0, 1) },
        "reserved1" => { kind: Unsigned, derived: false, required: false, description: "Reserved 24 bits between the flags and the VNI", reflect_bounded: reserved1, VNI_MAX, layout: (1, 4) },
        "vni" => { kind: Unsigned, derived: false, required: true, description: "24-bit VXLAN network identifier", reflect_bounded: vni, VNI_MAX, layout: (4, 7) },
        "reserved2" => { kind: Unsigned, derived: false, required: false, description: "Reserved byte after the VNI", reflect: reserved2, layout: (7, 8) }
    }
    layout pub(crate) fn vxlan_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VxlanCodec;

impl LayerCodec for VxlanCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("vxlan")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Vxlan>()
            .ok_or_else(|| wrong_layer("vxlan", layer))?;
        ensure_encode_budget("vxlan", VXLAN_LEN, context)?;
        if layer.vni > VNI_MAX || layer.reserved1 > VNI_MAX {
            return Err(invalid("vxlan", "24-bit field exceeds its wire range"));
        }

        let mut diagnostics = Vec::new();
        // The header is only ever followed by its encapsulated frame; without
        // one the bytes dissect into a missing-required-child error. The
        // shared discriminator validation accepts a malformed child, so
        // dissected captures of truncated inner frames always rebuild.
        validate_raw_child_discriminator("vxlan", 0, context, &mut diagnostics)?;
        if layer.flags != VNI_VALID_FLAG {
            strict_or_diagnostic(
                "vxlan",
                "build.vxlan_flags",
                "flags",
                "RFC 7348 requires the VNI-valid flag set and every other flag bit clear",
                context,
                &mut diagnostics,
            )?;
        }
        if layer.reserved1 != 0 || layer.reserved2 != 0 {
            strict_or_diagnostic(
                "vxlan",
                "build.vxlan_reserved",
                "reserved1",
                "VXLAN reserved fields must be zero on transmission",
                context,
                &mut diagnostics,
            )?;
        }

        let mut prefix = Vec::with_capacity(VXLAN_LEN);
        prefix.push(layer.flags);
        prefix.extend_from_slice(&layer.reserved1.to_be_bytes()[1..]);
        prefix.extend_from_slice(&layer.vni.to_be_bytes()[1..]);
        prefix.push(layer.reserved2);
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(layer.clone()),
            fields: vxlan_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < VXLAN_LEN {
            return Err(truncated("vxlan", VXLAN_LEN, input.len()));
        }
        let flags = input[0];
        let reserved1 = u32::from_be_bytes([0, input[1], input[2], input[3]]);
        let vni = u32::from_be_bytes([0, input[4], input[5], input[6]]);
        let reserved2 = input[7];

        let mut diagnostics = Vec::new();
        if flags != VNI_VALID_FLAG {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.vxlan_flags",
                    "VXLAN flags deviate from the single defined VNI-valid bit",
                )
                .at_field("flags"),
            );
        }
        if reserved1 != 0 || reserved2 != 0 {
            diagnostics.push(
                Diagnostic::warning("decode.vxlan_reserved", "VXLAN reserved bits are non-zero")
                    .at_field("reserved1"),
            );
        }
        let layer = Vxlan {
            flags,
            vni,
            reserved1,
            reserved2,
        };
        let payload_len = input.len() - VXLAN_LEN;
        Ok(DecodedLayerValue {
            fields: vxlan_layout(),
            layer: Box::new(layer),
            consumed: VXLAN_LEN,
            payload_len,
            // The encapsulated frame is always Ethernet.
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
        make_layer(Vxlan::default(), fields)
    }
}
