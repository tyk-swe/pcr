// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

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
    ValueExpectation, ensure_encode_budget, expected_discriminator_for_value, invalid, make_layer,
    out_of_range, payload_without_padding, protocol, resolve_u16, strict_or_diagnostic, truncated,
    validate_auto_raw_discriminator, validate_raw_child_discriminator, wrong_layer, wrong_type,
};

const PPPOE_LEN: usize = 6;
const PPP_LEN: usize = 2;

/// Discriminator for a session-stage payload: a PPP frame.
pub(crate) const PPPOE_SESSION: u64 = 0;
/// Discriminator for a discovery-stage payload: opaque tag bytes.
pub(crate) const PPPOE_DISCOVERY: u64 = 1;

/// PPPoE header (RFC 2516), covering both stages.
///
/// A zero `code` is session-stage data whose payload is a PPP frame; any
/// other code is a discovery packet — PADI, PADO, PADR, PADS, PADT — whose
/// tag list is preserved as opaque payload bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pppoe {
    /// 4-bit version; RFC 2516 defines only version 1.
    pub version: u8,
    /// 4-bit type; RFC 2516 defines only type 1.
    pub kind: u8,
    /// Stage code: zero for session data, a discovery code otherwise.
    pub code: u8,
    /// Session identifier assigned during discovery.
    pub session_id: u16,
    /// Payload length in bytes, excluding this header.
    pub length: WireValue<u16>,
}

impl Default for Pppoe {
    fn default() -> Self {
        Self {
            version: 1,
            kind: 1,
            code: 0,
            session_id: 0,
            length: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn pppoe_schema() => { protocol: protocol("pppoe"), name: "PPPoE" }
    impl Pppoe {
        "version" => { kind: Unsigned, derived: false, required: false, description: "4-bit PPPoE version; only version 1 is defined", get |layer| Some(reflect_get(&layer.version)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.version = u8::try_from(value).ok().filter(|value| *value <= 0xf).ok_or_else(|| out_of_range(pppoe_schema(), name))?; Ok(()) }, _ => Err(wrong_type(pppoe_schema(), name, "unsigned")) }, layout: (0, 1) },
        "type" => { kind: Unsigned, derived: false, required: false, description: "4-bit PPPoE type; only type 1 is defined", get |layer| Some(reflect_get(&layer.kind)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.kind = u8::try_from(value).ok().filter(|value| *value <= 0xf).ok_or_else(|| out_of_range(pppoe_schema(), name))?; Ok(()) }, _ => Err(wrong_type(pppoe_schema(), name, "unsigned")) }, layout: (0, 1) },
        "code" => { kind: Unsigned, derived: false, required: false, description: "Stage code: zero for session data, a discovery code otherwise", get |layer| Some(reflect_get(&layer.code)), set |layer, value, name| reflect_set(&mut layer.code, pppoe_schema(), name, value), layout: (1, 2) },
        "session_id" => { kind: Unsigned, derived: false, required: true, description: "Session identifier assigned during discovery", get |layer| Some(reflect_get(&layer.session_id)), set |layer, value, name| reflect_set(&mut layer.session_id, pppoe_schema(), name, value), layout: (2, 4) },
        "length" => { kind: Unsigned, derived: true, required: false, description: "Payload length excluding the header", get |layer| Some(reflect_get(&layer.length)), set |layer, value, name| reflect_set(&mut layer.length, pppoe_schema(), name, value), layout: (4, 6) },
        normalize |layer| { layer.length.normalize(); }
    }
    layout pub(crate) fn pppoe_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PppoeCodec;

impl LayerCodec for PppoeCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("pppoe")
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
            .downcast_ref::<Pppoe>()
            .ok_or_else(|| wrong_layer("pppoe", layer))?;
        ensure_encode_budget("pppoe", PPPOE_LEN, context)?;
        if layer.version > 0xf || layer.kind > 0xf {
            return Err(invalid("pppoe", "field exceeds its wire range"));
        }
        let covered_payload = payload_without_padding("pppoe", payload, context)?;
        let expected_length = u16::try_from(covered_payload.len())
            .map_err(|_| invalid("pppoe", "payload exceeds the PPPoE length range"))?;

        let mut diagnostics = Vec::new();
        if layer.version != 1 || layer.kind != 1 {
            strict_or_diagnostic(
                "pppoe",
                "build.pppoe_version",
                "version",
                "RFC 2516 defines only PPPoE version 1, type 1",
                context,
                &mut diagnostics,
            )?;
        }
        // The stage code decides how the payload dissects: zero selects a
        // PPP frame, anything else opaque discovery tags. A disagreeing
        // child would come back as different layers, and a session header
        // with no payload at all is missing its mandatory PPP frame — only
        // discovery packets like PADT are complete without one.
        let expected_stage = match context.child.map(|child| child.protocol_id().as_str()) {
            Some("ppp") => Some(0_u8),
            Some("malformed") => None,
            _ => Some(1),
        };
        if let Some(expected) = expected_stage
            && (layer.code == 0) != (expected == 0)
        {
            strict_or_diagnostic(
                "pppoe",
                "build.pppoe_stage",
                "code",
                match (expected, context.child.is_some()) {
                    (0, _) => "a PPP payload requires the zero session-stage code",
                    (_, true) => "a non-PPP payload requires a non-zero discovery code",
                    (_, false) => {
                        "session data must carry a PPP frame; only discovery packets are complete without a payload"
                    }
                },
                context,
                &mut diagnostics,
            )?;
        }
        // The enclosing EtherType names the stage too. An Auto ether_type
        // resolves to the session value 0x8864, so a discovery frame must
        // carry an explicit 0x8863 or it will not dissect as discovery. The
        // cooked-capture headers spell the same discriminator "protocol".
        let expected_ether_type = if layer.code == 0 { 0x8864 } else { 0x8863 };
        let parent_ether_type = context
            .index
            .checked_sub(1)
            .and_then(|index| context.packet.layer(index))
            .and_then(|parent| {
                parent
                    .field("ether_type")
                    .or_else(|| parent.field("protocol"))
            });
        let ether_type_disagrees = match &parent_ether_type {
            Some(FieldValue::Unsigned(value @ (0x8863 | 0x8864))) => *value != expected_ether_type,
            // Auto reflects as text and materializes the session EtherType.
            Some(FieldValue::Text(_)) => layer.code != 0,
            _ => false,
        };
        if ether_type_disagrees {
            strict_or_diagnostic(
                "pppoe",
                "build.pppoe_stage",
                "code",
                format!(
                    "stage code {} requires the enclosing EtherType 0x{expected_ether_type:04x}",
                    layer.code
                ),
                context,
                &mut diagnostics,
            )?;
        }
        let (length, materialized_length) = resolve_u16(
            "pppoe",
            "length",
            &layer.length,
            ValueExpectation::Required(expected_length),
            context.mode,
            &mut diagnostics,
        )?;

        let mut prefix = Vec::with_capacity(PPPOE_LEN);
        prefix.push((layer.version << 4) | layer.kind);
        prefix.push(layer.code);
        prefix.extend_from_slice(&layer.session_id.to_be_bytes());
        prefix.extend_from_slice(&length.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.length = materialized_length;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: pppoe_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < PPPOE_LEN {
            return Err(truncated("pppoe", PPPOE_LEN, input.len()));
        }
        let version = input[0] >> 4;
        let kind = input[0] & 0x0f;
        let code = input[1];
        let session_id = u16::from_be_bytes([input[2], input[3]]);
        let length = usize::from(u16::from_be_bytes([input[4], input[5]]));
        if input.len() - PPPOE_LEN < length {
            return Err(truncated("pppoe", PPPOE_LEN + length, input.len()));
        }

        let mut diagnostics = Vec::new();
        if version != 1 || kind != 1 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.pppoe_version",
                    "PPPoE version or type deviates from the defined value 1",
                )
                .at_field("version"),
            );
        }
        // The EtherType that selected this layer is authoritative for the
        // stage; the code is a heuristic fallback for roots and synthetic
        // parents. A disagreeing code never turns discovery tags into a PPP
        // frame or session data into tags.
        let discovery = match context.discriminator.map(|discriminator| discriminator.0) {
            Some(0x8863) => true,
            Some(0x8864) => false,
            _ => code != 0,
        };
        if discovery != (code != 0) {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.pppoe_stage",
                    "the stage code disagrees with the enclosing EtherType",
                )
                .at_field("code"),
            );
        }
        let layer = Pppoe {
            version,
            kind,
            code,
            session_id,
            length: WireValue::Exact(length as u16),
        };
        Ok(DecodedLayerValue {
            fields: pppoe_layout(),
            layer: Box::new(layer),
            consumed: PPPOE_LEN,
            payload_offset: PPPOE_LEN,
            payload_len: length,
            next: if !discovery {
                // Session payloads must start with the PPP protocol field,
                // so an empty session frame surfaces the missing header
                // rather than dissecting as complete.
                vec![Discriminator(PPPOE_SESSION)]
            } else if length == 0 {
                // A tag-free discovery packet — PADT — is complete.
                Vec::new()
            } else {
                vec![Discriminator(PPPOE_DISCOVERY)]
            },
            diagnostics,
            stop: discovery && length == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Pppoe::default(), fields)
    }
}

/// PPP frame header as carried by PPPoE session data (RFC 1661): the 2-byte
/// protocol field that selects the network payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ppp {
    /// PPP protocol number: 0x0021 IPv4, 0x0057 IPv6, 0xc021 LCP, ….
    pub protocol: WireValue<u16>,
}

impl Default for Ppp {
    fn default() -> Self {
        Self {
            protocol: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn ppp_schema() => { protocol: protocol("ppp"), name: "PPP" }
    impl Ppp {
        "protocol" => { kind: Unsigned, derived: true, required: false, description: "PPP protocol number selecting the payload", get |layer| Some(reflect_get(&layer.protocol)), set |layer, value, name| reflect_set(&mut layer.protocol, ppp_schema(), name, value), layout: (0, 2) },
        normalize |layer| { layer.protocol.normalize(); }
    }
    layout pub(crate) fn ppp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PppCodec;

impl LayerCodec for PppCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ppp")
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
            .downcast_ref::<Ppp>()
            .ok_or_else(|| wrong_layer("ppp", layer))?;
        ensure_encode_budget("ppp", PPP_LEN, context)?;

        let mut diagnostics = Vec::new();
        validate_auto_raw_discriminator(
            "ppp",
            "protocol",
            &layer.protocol,
            context,
            &mut diagnostics,
        )?;
        let (protocol_number, materialized_protocol) = resolve_u16(
            "ppp",
            "protocol",
            &layer.protocol,
            expected_discriminator_for_value("ppp", context, 0_u16, &layer.protocol),
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "ppp",
            u64::from(protocol_number),
            context,
            &mut diagnostics,
        )?;

        Ok(EncodedLayer {
            prefix: protocol_number.to_be_bytes().to_vec(),
            suffix: Vec::new(),
            materialized: Box::new(Ppp {
                protocol: materialized_protocol,
            }),
            fields: ppp_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < PPP_LEN {
            return Err(truncated("ppp", PPP_LEN, input.len()));
        }
        let protocol_number = u16::from_be_bytes([input[0], input[1]]);
        let payload_len = input.len() - PPP_LEN;
        // Unregistered protocols — LCP, IPCP, CHAP — fall through to the
        // typed raw child rather than a diagnostic, mirroring UDP ports.
        let mut next = Vec::with_capacity(2);
        if protocol_number != 0 {
            next.push(Discriminator(u64::from(protocol_number)));
        }
        next.push(Discriminator(0));
        Ok(DecodedLayerValue {
            fields: ppp_layout(),
            layer: Box::new(Ppp {
                protocol: WireValue::Exact(protocol_number),
            }),
            consumed: PPP_LEN,
            payload_offset: PPP_LEN,
            payload_len,
            next: if payload_len == 0 { Vec::new() } else { next },
            diagnostics: Vec::new(),
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Ppp::default(), fields)
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
    fn session_data_selects_ppp_and_discovery_selects_opaque_tags() {
        let registry = ProtocolRegistry::default();

        let session = PppoeCodec
            .decode(
                &[0x11, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x21],
                &decode_context(&registry),
            )
            .unwrap();
        let pppoe = session.layer.as_any().downcast_ref::<Pppoe>().unwrap();
        assert_eq!(pppoe.session_id, 0x1234);
        assert_eq!(session.next, vec![Discriminator(PPPOE_SESSION)]);
        assert!(session.diagnostics.is_empty());

        let empty_session = PppoeCodec
            .decode(
                &[0x11, 0x00, 0x12, 0x34, 0x00, 0x00],
                &decode_context(&registry),
            )
            .unwrap();
        assert_eq!(empty_session.next, vec![Discriminator(PPPOE_SESSION)]);
        assert!(!empty_session.stop);

        let discovery = PppoeCodec
            .decode(
                &[0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4],
                &decode_context(&registry),
            )
            .unwrap();
        assert_eq!(discovery.next, vec![Discriminator(PPPOE_DISCOVERY)]);

        // The declared length bounds the payload even when more bytes follow.
        let deviant = PppoeCodec
            .decode(&[0x21, 0x00, 0, 0, 0x00, 0x00], &decode_context(&registry))
            .unwrap();
        assert_eq!(deviant.diagnostics[0].code, "decode.pppoe_version");
        assert!(matches!(
            PppoeCodec.decode(
                &[0x11, 0x00, 0, 0, 0x00, 0x05, 1, 2],
                &decode_context(&registry)
            ),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn the_entry_ethertype_outranks_a_disagreeing_stage_code() {
        let registry = ProtocolRegistry::default();
        let context = |discriminator| LayerDecodeContext {
            registry: &registry,
            layer_index: 1,
            absolute_offset: 14,
            verify_checksums: false,
            allow_trailing_padding: false,
            network: None,
            discriminator: Some(Discriminator(discriminator)),
        };
        // A discovery-EtherType frame whose payload imitates PPP/IPv4 stays
        // opaque instead of dissecting as session data.
        let bytes = [0x11, 0x00, 0, 0, 0x00, 0x02, 0x00, 0x21];

        let discovery = PppoeCodec.decode(&bytes, &context(0x8863)).unwrap();
        assert_eq!(discovery.next, vec![Discriminator(PPPOE_DISCOVERY)]);
        assert_eq!(discovery.diagnostics[0].code, "decode.pppoe_stage");

        let session = PppoeCodec.decode(&bytes, &context(0x8864)).unwrap();
        assert_eq!(session.next, vec![Discriminator(PPPOE_SESSION)]);
        assert!(session.diagnostics.is_empty());

        // The session EtherType stays authoritative when the code disagrees.
        let bad_code = [0x11, 0x09, 0, 0, 0x00, 0x02, 0x00, 0x21];
        let warned = PppoeCodec.decode(&bad_code, &context(0x8864)).unwrap();
        assert_eq!(warned.next, vec![Discriminator(PPPOE_SESSION)]);
        assert_eq!(warned.diagnostics[0].code, "decode.pppoe_stage");
    }

    #[test]
    fn ppp_offers_its_protocol_then_the_raw_fallback() {
        let registry = ProtocolRegistry::default();
        let lcp = PppCodec
            .decode(&[0xc0, 0x21, 0x01, 0x01], &decode_context(&registry))
            .unwrap();
        let ppp = lcp.layer.as_any().downcast_ref::<Ppp>().unwrap();
        assert_eq!(ppp.protocol, WireValue::Exact(0xc021));
        assert_eq!(lcp.next, vec![Discriminator(0xc021), Discriminator(0)]);

        assert!(matches!(
            PppCodec.decode(&[0x00], &decode_context(&registry)),
            Err(CodecError::Truncated { .. })
        ));
    }
}
