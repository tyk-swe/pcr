// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, Malformed, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    ValueExpectation, ensure_encode_budget, invalid, make_layer, payload_without_padding, protocol,
    resolve_u16, resolve_u16_discriminator, strict_or_diagnostic, truncated, typed_layer,
};

use crate::protocol::BuiltinProtocol;

const PPPOE_NAME: &str = BuiltinProtocol::Pppoe.as_str();
const PPP_NAME: &str = BuiltinProtocol::Ppp.as_str();

const PPPOE_LEN: usize = 6;
const PPP_LEN: usize = 2;

pub(crate) const PPPOE_SESSION: u64 = 0;
pub(crate) const PPPOE_DISCOVERY: u64 = 1;

/// PPPoE header (RFC 2516), covering both stages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pppoe {
    pub version: u8,
    pub type_code: u8,
    pub code: u8,
    pub session_id: u16,
    /// Payload length in bytes, excluding this header.
    pub length: WireValue<u16>,
}

impl Default for Pppoe {
    fn default() -> Self {
        Self {
            version: 1,
            type_code: 1,
            code: 0,
            session_id: 0,
            length: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn pppoe_schema() => { protocol: protocol(PPPOE_NAME), name: "PPPoE" }
    impl Pppoe {
        "version" => { kind: Unsigned, derived: false, required: false, description: "4-bit PPPoE version; only version 1 is defined", reflect_bounded: version, 0xf_u64, layout: (0, 1) },
        "type" => { kind: Unsigned, derived: false, required: false, description: "4-bit PPPoE type; only type 1 is defined", reflect_bounded: type_code, 0xf_u64, layout: (0, 1) },
        "code" => { kind: Unsigned, derived: false, required: false, description: "Stage code: zero for session data, a discovery code otherwise", reflect: code, layout: (1, 2) },
        "session_id" => { kind: Unsigned, derived: false, required: true, description: "Session identifier assigned during discovery", reflect: session_id, layout: (2, 4) },
        "length" => { kind: Unsigned, derived: true, required: false, description: "Payload length excluding the header", reflect: length, layout: (4, 6) },
    }
    layout pub(crate) fn pppoe_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PppoeCodec;

impl LayerCodec for PppoeCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &pppoe_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Pppoe>(PPPOE_NAME, layer)?;
        ensure_encode_budget(PPPOE_NAME, PPPOE_LEN, context)?;
        if layer.version > 0xf || layer.type_code > 0xf {
            return Err(invalid(PPPOE_NAME, "field exceeds its wire range"));
        }
        let covered_payload = payload_without_padding(PPPOE_NAME, payload, context)?;
        let expected_length = u16::try_from(covered_payload.len())
            .map_err(|_| invalid(PPPOE_NAME, "payload exceeds the PPPoE length range"))?;

        let mut diagnostics = validate_stage(layer, context)?;
        let (length, materialized_length) = resolve_u16(
            PPPOE_NAME,
            "length",
            &layer.length,
            ValueExpectation::Required(expected_length),
            context.mode,
            &mut diagnostics,
        )?;

        let mut prefix = Vec::with_capacity(PPPOE_LEN);
        prefix.push((layer.version << 4) | layer.type_code);
        prefix.push(layer.code);
        prefix.extend_from_slice(&layer.session_id.to_be_bytes());
        prefix.extend_from_slice(&length.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.length = materialized_length;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(pppoe_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<PPPOE_LEN>() else {
            return Err(truncated(PPPOE_NAME, PPPOE_LEN, input.len()));
        };
        let version = header[0] >> 4;
        let type_code = header[0] & 0x0f;
        let code = header[1];
        let session_id = u16::from_be_bytes([header[2], header[3]]);
        let length_field = u16::from_be_bytes([header[4], header[5]]);
        let length = usize::from(length_field);
        if input.len().saturating_sub(PPPOE_LEN) < length {
            return Err(truncated(
                PPPOE_NAME,
                PPPOE_LEN.saturating_add(length),
                input.len(),
            ));
        }

        let mut diagnostics = Vec::new();
        if version != 1 || type_code != 1 {
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
        // parents.
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
            type_code,
            code,
            session_id,
            length: WireValue::Exact(length_field),
        };
        Ok(DecodedLayer {
            fields: pppoe_layout(),
            layer: Box::new(layer),
            consumed: PPPOE_LEN,
            payload_len: length,
            next: if !discovery {
                vec![Discriminator(PPPOE_SESSION)]
            } else if length == 0 {
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Pppoe::default(), fields)
    }
}

fn validate_stage(
    layer: &Pppoe,
    context: &LayerEncodeContext<'_>,
) -> Result<Vec<Diagnostic>, crate::codec::Error> {
    let mut diagnostics = Vec::new();
    if layer.version != 1 || layer.type_code != 1 {
        strict_or_diagnostic(
            PPPOE_NAME,
            "build.pppoe_version",
            "version",
            "RFC 2516 defines only PPPoE version 1, type 1",
            context,
            &mut diagnostics,
        )?;
    }
    let expected_stage = match context.child {
        Some(child) if child.is::<Ppp>() => Some(0_u8),
        Some(child) if child.is::<Malformed>() => None,
        _ => Some(1),
    };
    if let Some(expected) = expected_stage
        && (layer.code == 0) != (expected == 0)
    {
        let message = match (expected, context.child.is_some()) {
            (0, _) => "a PPP payload requires the zero session-stage code",
            (_, true) => "a non-PPP payload requires a non-zero discovery code",
            (_, false) => {
                "session data must carry a PPP frame; only discovery packets are complete without a payload"
            }
        };
        strict_or_diagnostic(
            PPPOE_NAME,
            "build.pppoe_stage",
            "code",
            message,
            context,
            &mut diagnostics,
        )?;
    }
    validate_parent_stage(layer, context, &mut diagnostics)?;
    Ok(diagnostics)
}

fn validate_parent_stage(
    layer: &Pppoe,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), crate::codec::Error> {
    let expected_ether_type = if layer.code == 0 { 0x8864 } else { 0x8863 };
    let parent_ether_type = context
        .index
        .checked_sub(1)
        .and_then(|index| context.packet.layer(index))
        .and_then(|parent| {
            parent
                .field("ether_type")
                .or_else(|| parent.field("protocol"))
                .or_else(|| parent.field("protocol_type"))
                .or_else(|| {
                    (parent.field("oui") == Some(FieldValue::Unsigned(0)))
                        .then(|| parent.field("protocol_id"))
                        .flatten()
                })
        });
    let disagrees = match &parent_ether_type {
        Some(FieldValue::Unsigned(value @ (0x8863 | 0x8864))) => *value != expected_ether_type,
        Some(FieldValue::Text(_)) => layer.code != 0,
        _ => false,
    };
    if disagrees {
        strict_or_diagnostic(
            PPPOE_NAME,
            "build.pppoe_stage",
            "code",
            format!(
                "stage code {} requires the enclosing EtherType 0x{expected_ether_type:04x}",
                layer.code
            ),
            context,
            diagnostics,
        )?;
    }
    Ok(())
}

/// PPP frame header as carried by PPPoE session data (RFC 1661).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ppp {
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
    fn ppp_schema() => { protocol: protocol(PPP_NAME), name: "PPP" }
    impl Ppp {
        "protocol" => { kind: Unsigned, derived: true, required: false, description: "PPP protocol number selecting the payload", reflect: protocol, layout: (0, 2) },
    }
    layout pub(crate) fn ppp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PppCodec;

impl LayerCodec for PppCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &ppp_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Ppp>(PPP_NAME, layer)?;
        ensure_encode_budget(PPP_NAME, PPP_LEN, context)?;

        let mut diagnostics = Vec::new();
        let (protocol_number, materialized_protocol) = resolve_u16_discriminator(
            PPP_NAME,
            "protocol",
            &layer.protocol,
            context,
            &mut diagnostics,
        )?;

        Ok(EncodedLayer::header(
            protocol_number.to_be_bytes().to_vec(),
            Box::new(Ppp {
                protocol: materialized_protocol,
            }),
        )
        .with_fields(ppp_layout())
        .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<PPP_LEN>() else {
            return Err(truncated(PPP_NAME, PPP_LEN, input.len()));
        };
        let protocol_number = u16::from_be_bytes([header[0], header[1]]);
        let payload_len = input.len().saturating_sub(PPP_LEN);
        let mut next = Vec::with_capacity(2);
        if protocol_number != 0 {
            next.push(Discriminator(u64::from(protocol_number)));
        }
        next.push(Discriminator(0));
        Ok(DecodedLayer {
            fields: ppp_layout(),
            layer: Box::new(Ppp {
                protocol: WireValue::Exact(protocol_number),
            }),
            consumed: PPP_LEN,
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Ppp::default(), fields)
    }
}
