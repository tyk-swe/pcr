// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, ensure_encode_budget, invalid, make_layer, out_of_range, protocol,
    resolve_u16, strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_raw_child_discriminator, validate_typed_child_discriminator, wrong_layer, wrong_type,
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
        "dsap" => { kind: Unsigned, derived: false, required: true, description: "Destination service access point", get |layer| Some(reflect_get(&layer.dsap)), set |layer, value, name| reflect_set(&mut layer.dsap, llc_schema(), name, value), layout: (0, 1) },
        "ssap" => { kind: Unsigned, derived: false, required: true, description: "Source service access point", get |layer| Some(reflect_get(&layer.ssap)), set |layer, value, name| reflect_set(&mut layer.ssap, llc_schema(), name, value), layout: (1, 2) },
        "control" => { kind: Bytes, derived: false, required: true, description: "Control field: one byte for U format, two for I and S formats", get |layer| Some(reflect_get(&layer.control)), set |layer, value, name| reflect_set(&mut layer.control, llc_schema(), name, value), layout: (2, control_end) }
    }
    layout pub(crate) fn llc_layout(control_end: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LlcCodec;

impl LayerCodec for LlcCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("llc")
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
        let header_len = 2 + layer.control.len();
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
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < LLC_MIN_LEN {
            return Err(truncated("llc", LLC_MIN_LEN, input.len()));
        }
        let control_len = if input[2] & U_FORMAT_MASK == U_FORMAT_MASK {
            1
        } else {
            2
        };
        let header_len = 2 + control_len;
        if input.len() < header_len {
            return Err(truncated("llc", header_len, input.len()));
        }
        let dsap = input[0];
        let ssap = input[1];
        let payload_len = input.len() - header_len;
        let sap_pair = (u64::from(dsap) << 8) | u64::from(ssap);
        // Unregistered SAP pairs fall through to the typed raw child, like
        // UDP ports and PPP protocol numbers. Only an unnumbered-information
        // frame carries an upper protocol's payload; everything else is LLC
        // control traffic and stays opaque.
        let mut next = Vec::with_capacity(2);
        if sap_pair != 0 && is_ui_control(&input[2..header_len]) {
            next.push(Discriminator(sap_pair));
        }
        next.push(Discriminator(0));
        Ok(DecodedLayerValue {
            fields: llc_layout(header_len),
            layer: Box::new(Llc {
                dsap,
                ssap,
                control: Bytes::copy_from_slice(&input[2..header_len]),
            }),
            consumed: header_len,
            payload_offset: header_len,
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
    ) -> Result<Box<dyn Layer>, CodecError> {
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
        "oui" => { kind: Unsigned, derived: false, required: true, description: "Organizationally unique identifier; zero selects the EtherType space", get |layer| Some(FieldValue::from(layer.oui)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.oui = u32::try_from(value).ok().filter(|value| *value <= OUI_MAX).ok_or_else(|| out_of_range(snap_schema(), name))?; Ok(()) }, _ => Err(wrong_type(snap_schema(), name, "unsigned")) }, layout: (0, 3) },
        "protocol_id" => { kind: Unsigned, derived: true, required: false, description: "Protocol identifier within the OUI's numbering", get |layer| Some(reflect_get(&layer.protocol_id)), set |layer, value, name| reflect_set(&mut layer.protocol_id, snap_schema(), name, value), layout: (3, 5) },
        normalize |layer| { layer.protocol_id.normalize(); }
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
    fn protocol_id(&self) -> ProtocolId {
        protocol("snap")
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
            expected_snap_discriminator(context, &layer.protocol_id)
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
        prefix.extend_from_slice(&layer.oui.to_be_bytes()[1..]);
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
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < SNAP_LEN {
            return Err(truncated("snap", SNAP_LEN, input.len()));
        }
        let oui = u32::from_be_bytes([0, input[0], input[1], input[2]]);
        let protocol_id = u16::from_be_bytes([input[3], input[4]]);
        let payload_len = input.len() - SNAP_LEN;
        Ok(DecodedLayerValue {
            fields: snap_layout(),
            layer: Box::new(Snap {
                oui,
                protocol_id: WireValue::Exact(protocol_id),
            }),
            consumed: SNAP_LEN,
            payload_offset: SNAP_LEN,
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
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Snap::default(), fields)
    }
}

/// Like `expected_discriminator_for_value` but scoped to the SNAP zero-OUI
/// EtherType space, which shares no discriminators above 16 bits.
fn expected_snap_discriminator(
    context: &LayerEncodeContext<'_>,
    value: &WireValue<u16>,
) -> ValueExpectation<u16> {
    super::super::common::expected_discriminator_for_value("snap", context, 0_u16, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_packet::{
        Packet,
        build::{BuildContext, BuildMode},
        registry::ProtocolRegistry,
    };

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

    fn encode_context<'a>(
        packet: &'a Packet,
        build_context: &'a BuildContext,
        registry: &'a ProtocolRegistry,
        child: Option<&'a dyn Layer>,
    ) -> LayerEncodeContext<'a> {
        LayerEncodeContext {
            packet,
            index: 0,
            build_context,
            mode: BuildMode::Strict,
            registry,
            child,
            remaining_packet_bytes: usize::MAX,
        }
    }

    #[test]
    fn llc_reads_both_control_formats_and_offers_the_sap_pair() {
        let registry = ProtocolRegistry::default();

        let unnumbered = LlcCodec
            .decode(&[0xaa, 0xaa, 0x03, 0x00], &decode_context(&registry))
            .unwrap();
        let llc = unnumbered.layer.as_any().downcast_ref::<Llc>().unwrap();
        assert_eq!(llc.control.as_ref(), &[0x03]);
        assert_eq!(unnumbered.consumed, 3);
        assert_eq!(
            unnumbered.next,
            vec![Discriminator(0xaaaa), Discriminator(0)]
        );

        // Non-UI frames are LLC control traffic: their payload never
        // selects a typed child, whatever the SAP pair says.
        let supervisory = LlcCodec
            .decode(&[0x42, 0x42, 0x01, 0x05, 0xff], &decode_context(&registry))
            .unwrap();
        let llc = supervisory.layer.as_any().downcast_ref::<Llc>().unwrap();
        assert_eq!(llc.control.as_ref(), &[0x01, 0x05]);
        assert_eq!(supervisory.consumed, 4);
        assert_eq!(supervisory.next, vec![Discriminator(0)]);

        let test_frame = LlcCodec
            .decode(&[0xaa, 0xaa, 0xe3, 0x05], &decode_context(&registry))
            .unwrap();
        assert_eq!(test_frame.next, vec![Discriminator(0)]);

        assert!(matches!(
            LlcCodec.decode(&[0xaa, 0xaa], &decode_context(&registry)),
            Err(CodecError::Truncated { .. })
        ));
        assert!(matches!(
            LlcCodec.decode(&[0x42, 0x42, 0x01], &decode_context(&registry)),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn llc_accepts_ui_frames_with_the_poll_final_bit_set() {
        let registry = crate::builtin::registry().unwrap();
        let packet = Packet::new();
        let build_context = BuildContext::default();
        let child = Snap::default();
        let encoded = LlcCodec
            .encode(
                &Llc {
                    dsap: 0xaa,
                    ssap: 0xaa,
                    control: Bytes::from_static(&[0x13]),
                },
                &[],
                &encode_context(&packet, &build_context, &registry, Some(&child)),
            )
            .unwrap();

        assert_eq!(encoded.prefix, [0xaa, 0xaa, 0x13]);
        assert!(encoded.diagnostics.is_empty());

        let decoded = LlcCodec
            .decode(&[0xaa, 0xaa, 0x13, 0x00], &decode_context(&registry))
            .unwrap();
        assert_eq!(decoded.next, vec![Discriminator(0xaaaa), Discriminator(0)]);
    }

    #[test]
    fn snap_selects_the_ethertype_space_only_under_the_zero_oui() {
        let registry = ProtocolRegistry::default();

        let zero_oui = SnapCodec
            .decode(&[0, 0, 0, 0x08, 0x00, 0x45], &decode_context(&registry))
            .unwrap();
        assert_eq!(zero_oui.next, vec![Discriminator(0x0800)]);

        let cisco = SnapCodec
            .decode(
                &[0x00, 0x00, 0x0c, 0x20, 0x00, 0x01],
                &decode_context(&registry),
            )
            .unwrap();
        let snap = cisco.layer.as_any().downcast_ref::<Snap>().unwrap();
        assert_eq!(snap.oui, 0x0c);
        assert_eq!(cisco.next, vec![Discriminator(0x000c_2000)]);

        assert!(matches!(
            SnapCodec.decode(&[0, 0, 0, 0x08], &decode_context(&registry)),
            Err(CodecError::Truncated { .. })
        ));
    }
}
