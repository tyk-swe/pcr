// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, ensure_encode_budget, invalid, make_layer, protocol, resolve_u16,
    strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_raw_child_discriminator, validate_typed_child_discriminator, wrong_layer,
};

/// Synthetic discriminator selecting IEEE 802.2 LLC framing. An EtherType at
/// or below 1500 is an 802.3 payload length, and `Discriminator` is wide
/// enough that a sentinel above the 16-bit EtherType space can never collide
/// with a real EtherType, so every existing binding is untouched.
pub(crate) const LLC_FRAME_DISCRIMINATOR: u64 = 0x1_0000;
/// The largest 802.3 length; 1501–1535 are undefined, 1536+ are EtherTypes.
pub(crate) const MAX_FRAME_LENGTH: u16 = 1500;

const LLC_MIN_LEN: usize = 3;
const SNAP_LEN: usize = 5;
/// A U-format control field — low bits `11` — is one byte; I and S formats
/// carry a second byte.
const U_FORMAT_MASK: u8 = 0x03;
/// The poll/final bit in a U-format control byte.
const POLL_FINAL_MASK: u8 = 0x10;
/// The unnumbered-information control opcode with the poll/final bit clear.
/// Only UI frames carry an upper protocol's payload; I, S, and the other U
/// formats are LLC control traffic, so their payload never selects a typed
/// child.
const UI_CONTROL: u8 = 0x03;
const OUI_MAX: u32 = 0x00ff_ffff;
/// DSAP and SSAP 0xAA announce a SNAP header.
const SNAP_SAP: u8 = 0xaa;

fn is_ui_control(control: &[u8]) -> bool {
    matches!(control, [byte] if byte & !POLL_FINAL_MASK == UI_CONTROL)
}

/// IEEE 802.2 LLC header carried by an 802.3 length-framed payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Llc {
    /// Destination service access point.
    pub dsap: u8,
    /// Source service access point.
    pub ssap: u8,
    /// Control field: one byte for U format, two for I and S formats.
    pub control: Bytes,
}

impl Default for Llc {
    fn default() -> Self {
        Self {
            dsap: SNAP_SAP,
            ssap: SNAP_SAP,
            // Unnumbered information, the framing every chained protocol uses.
            control: Bytes::from_static(&[0x03]),
        }
    }
}

reflective_layer! {
    fn llc_schema() => { protocol: protocol("llc"), name: "LLC" }
    impl Llc {
        "dsap" => { kind: Unsigned, derived: false, required: true, description: "Destination service access point", reflect: dsap, layout: (0, 1) },
        "ssap" => { kind: Unsigned, derived: false, required: true, description: "Source service access point", reflect: ssap, layout: (1, 2) },
        "control" => { kind: Bytes, derived: false, required: true, description: "Control field: one byte for U format, two for I and S formats", reflect: control, layout: (2, control_end) }
    }
    layout pub(crate) fn llc_layout(control_end: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LlcCodec;

impl LayerCodec for LlcCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("llc")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = layer
            .as_any()
            .downcast_ref::<Llc>()
            .ok_or_else(|| wrong_layer("llc", layer))?;
        let expected_control_len = match layer.control.first() {
            Some(first) if first & U_FORMAT_MASK == U_FORMAT_MASK => 1,
            Some(_) => 2,
            None => {
                return Err(invalid("llc", "the control field is empty"));
            }
        };
        if layer.control.len() != expected_control_len {
            return Err(invalid(
                "llc",
                format!(
                    "this control format is exactly {expected_control_len} byte(s), got {}",
                    layer.control.len()
                ),
            ));
        }
        let header_len = layer.control.len().saturating_add(2);
        ensure_encode_budget("llc", header_len, context)?;

        let mut diagnostics = Vec::new();
        let sap_pair = (u64::from(layer.dsap) << 8) | u64::from(layer.ssap);
        if is_ui_control(layer.control.as_ref()) {
            validate_raw_child_discriminator("llc", sap_pair, context, &mut diagnostics)?;
            // An unregistered SAP pair dissects through the typed-raw
            // fallback, so a typed child needs the pair that announces it.
            validate_typed_child_discriminator("llc", sap_pair, context, &mut diagnostics)?;
        } else if let Some(child) = context.child
            && !matches!(
                child.protocol_id().as_str(),
                "raw" | "padding" | "malformed"
            )
        {
            // Only unnumbered-information frames carry an upper protocol's
            // payload, so dissection never selects a typed child here.
            strict_or_diagnostic(
                "llc",
                "build.llc_control",
                "control",
                format!(
                    "only an unnumbered-information LLC frame (control 0x03 or 0x13) carries a typed {} payload",
                    child.protocol_id()
                ),
                context,
                &mut diagnostics,
            )?;
        }

        let mut prefix = Vec::with_capacity(header_len);
        prefix.push(layer.dsap);
        prefix.push(layer.ssap);
        prefix.extend_from_slice(&layer.control);
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(layer.clone()),
            fields: llc_layout(header_len),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(head) = input.first_chunk::<LLC_MIN_LEN>() else {
            return Err(truncated("llc", LLC_MIN_LEN, input.len()));
        };
        let control_len: usize = if head[2] & U_FORMAT_MASK == U_FORMAT_MASK {
            1
        } else {
            2
        };
        let header_len = control_len.saturating_add(2);
        let Some(control) = input.get(2..header_len) else {
            return Err(truncated("llc", header_len, input.len()));
        };
        let dsap = head[0];
        let ssap = head[1];
        let payload_len = input.len().saturating_sub(header_len);
        let sap_pair = (u64::from(dsap) << 8) | u64::from(ssap);
        // Unregistered SAP pairs fall through to the typed raw child, like
        // UDP ports and PPP protocol numbers. Only an unnumbered-information
        // frame carries an upper protocol's payload; everything else is LLC
        // control traffic and stays opaque.
        let mut next = Vec::with_capacity(2);
        if sap_pair != 0 && is_ui_control(control) {
            next.push(Discriminator(sap_pair));
        }
        next.push(Discriminator(0));
        Ok(DecodedLayerValue {
            fields: llc_layout(header_len),
            layer: Box::new(Llc {
                dsap,
                ssap,
                control: Bytes::copy_from_slice(control),
            }),
            consumed: header_len,
            payload_len,
            // Kept even with no payload: a UI frame on a registered SAP
            // pair announces a header, so the decoder reports it missing,
            // exactly as strict build rejects the childless layer.
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
        make_layer(Llc::default(), fields)
    }
}

/// IEEE 802 SNAP extension: a 24-bit OUI and a 16-bit protocol identifier.
///
/// Under the zero OUI the protocol identifier is an EtherType, so the SNAP
/// layer selects the same children an Ethernet II frame would.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snap {
    /// Organizationally unique identifier; zero selects the EtherType space.
    pub oui: u32,
    /// Protocol identifier within the OUI's numbering.
    pub protocol_id: WireValue<u16>,
}

impl Default for Snap {
    fn default() -> Self {
        Self {
            oui: 0,
            protocol_id: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn snap_schema() => { protocol: protocol("snap"), name: "SNAP" }
    impl Snap {
        "oui" => { kind: Unsigned, derived: false, required: true, description: "Organizationally unique identifier; zero selects the EtherType space", reflect_bounded: oui, OUI_MAX, layout: (0, 3) },
        "protocol_id" => { kind: Unsigned, derived: true, required: false, description: "Protocol identifier within the OUI's numbering", reflect: protocol_id, layout: (3, 5) },
    }
    layout pub(crate) fn snap_layout();
}

/// The discriminator a SNAP header offers: the plain EtherType under the
/// zero OUI, or the OUI and protocol identifier packed above the EtherType
/// space for vendor numberings.
pub(crate) fn snap_discriminator(oui: u32, protocol_id: u16) -> u64 {
    if oui == 0 {
        u64::from(protocol_id)
    } else {
        (u64::from(oui) << 16) | u64::from(protocol_id)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SnapCodec;

impl LayerCodec for SnapCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("snap")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = layer
            .as_any()
            .downcast_ref::<Snap>()
            .ok_or_else(|| wrong_layer("snap", layer))?;
        ensure_encode_budget("snap", SNAP_LEN, context)?;
        if layer.oui > OUI_MAX {
            return Err(invalid("snap", "the OUI exceeds its 24-bit wire range"));
        }

        let mut diagnostics = Vec::new();
        validate_auto_raw_discriminator(
            "snap",
            "protocol_id",
            &layer.protocol_id,
            context,
            &mut diagnostics,
        )?;
        let expectation = if layer.oui == 0 {
            // The zero OUI is the EtherType space, so the child derives the
            // identifier exactly as it would under Ethernet II.
            super::super::common::expected_discriminator_for_value(
                "snap",
                context,
                0_u16,
                &layer.protocol_id,
            )
        } else if matches!(layer.protocol_id, WireValue::Auto) {
            return Err(invalid(
                "snap",
                "an Auto protocol_id resolves only under the zero OUI; vendor numberings need an explicit value",
            ));
        } else {
            ValueExpectation::Suggested(0)
        };
        let (protocol_id, materialized_protocol_id) = resolve_u16(
            "snap",
            "protocol_id",
            &layer.protocol_id,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "snap",
            snap_discriminator(layer.oui, protocol_id),
            context,
            &mut diagnostics,
        )?;
        // A typed child must be selected by the emitted discriminator — a
        // registered vendor binding under a nonzero OUI, a bound EtherType
        // under the zero OUI — or dissection would fall back to raw bytes.
        validate_typed_child_discriminator(
            "snap",
            snap_discriminator(layer.oui, protocol_id),
            context,
            &mut diagnostics,
        )?;

        let mut prefix = Vec::with_capacity(SNAP_LEN);
        // The OUI is 24 bits, so the high byte of the big-endian word is
        // dropped; the range guard above proves it is zero.
        let [_, oui_high, oui_mid, oui_low] = layer.oui.to_be_bytes();
        prefix.extend_from_slice(&[oui_high, oui_mid, oui_low]);
        prefix.extend_from_slice(&protocol_id.to_be_bytes());
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(Snap {
                oui: layer.oui,
                protocol_id: materialized_protocol_id,
            }),
            fields: snap_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(header) = input.first_chunk::<SNAP_LEN>() else {
            return Err(truncated("snap", SNAP_LEN, input.len()));
        };
        let oui = u32::from_be_bytes([0, header[0], header[1], header[2]]);
        let protocol_id = u16::from_be_bytes([header[3], header[4]]);
        let payload_len = input.len().saturating_sub(SNAP_LEN);
        Ok(DecodedLayerValue {
            fields: snap_layout(),
            layer: Box::new(Snap {
                oui,
                protocol_id: WireValue::Exact(protocol_id),
            }),
            consumed: SNAP_LEN,
            payload_len,
            next: vec![Discriminator(snap_discriminator(oui, protocol_id))],
            diagnostics: Vec::new(),
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Snap::default(), fields)
    }
}
