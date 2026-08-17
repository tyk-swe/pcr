// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ethernet II frame model and codec.

use std::collections::BTreeMap;

use crate::{
    codec::{
        DecodedLayerValue, EncodedLayer, Error as CodecError, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Id as ProtocolId, Layer, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, aliased_fields, binding_protocol, expected_discriminator_for_value, invalid,
    make_layer, payload_without_padding, protocol, resolve_u16, strict_or_diagnostic, truncated,
    validate_auto_raw_discriminator, validate_raw_child_discriminator, wrong_layer,
};
use super::llc::{LLC_FRAME_DISCRIMINATOR, MAX_FRAME_LENGTH};

const ETHERNET_LEN: usize = 14;
const LINK_RAW_FALLBACK_DISCRIMINATOR: u16 = MAX_FRAME_LENGTH + 1;

/// The 802.3 length-versus-EtherType split shared by Ethernet II and the
/// VLAN tags: a value at or below 1500 is a payload length framing an LLC
/// header, 1536 and above is an EtherType, and the undefined band between
/// them falls through to the raw payload.
pub(super) fn link_payload_selection(
    name: &str,
    ether_type: u16,
    available: usize,
    header_len: usize,
) -> Result<(usize, Vec<Discriminator>), CodecError> {
    if ether_type >= 0x0600 {
        return Ok((available, vec![Discriminator(u64::from(ether_type))]));
    }
    if ether_type <= MAX_FRAME_LENGTH {
        let length = usize::from(ether_type);
        if length > available {
            return Err(truncated(name, header_len + length, header_len + available));
        }
        // A zero-length frame is complete: there is no LLC header to select.
        let next = if length == 0 {
            Vec::new()
        } else {
            vec![Discriminator(LLC_FRAME_DISCRIMINATOR)]
        };
        return Ok((length, next));
    }
    // 1501–1535: neither a length nor an EtherType; the unknown
    // discriminator preserves the payload as raw with a warning.
    Ok((available, vec![Discriminator(u64::from(ether_type))]))
}

/// Resolves the `ether_type` expectation for a link header: the encoded
/// payload length when an LLC frame follows — including a malformed layer
/// preserving broken LLC bytes from a length-framed capture — and the
/// registered discriminator otherwise.
pub(super) fn link_type_expectation(
    name: &str,
    context: &LayerEncodeContext<'_>,
    value: &WireValue<u16>,
    covered_payload_len: usize,
) -> Result<ValueExpectation<u16>, CodecError> {
    if context
        .child
        .is_some_and(|child| binding_protocol(child).as_str() == "llc")
    {
        let length = u16::try_from(covered_payload_len)
            .ok()
            .filter(|length| *length <= MAX_FRAME_LENGTH)
            .ok_or_else(|| {
                invalid(
                    name,
                    format!("an 802.3 frame length exceeds {MAX_FRAME_LENGTH} bytes"),
                )
            })?;
        return Ok(ValueExpectation::Required(length));
    }
    if matches!(value, WireValue::Auto)
        && context
            .child
            .is_some_and(|child| child.protocol_id().as_str() == "raw")
    {
        return Ok(ValueExpectation::Suggested(LINK_RAW_FALLBACK_DISCRIMINATOR));
    }
    Ok(expected_discriminator_for_value(
        name, context, 0_u16, value,
    ))
}

/// Rejects a length-form `ether_type` over anything other than LLC framing:
/// dissection treats every value at or below 1500 as an 802.3 payload
/// length and selects an LLC header, so any other child would come back as
/// a different layer stack. The zero-length empty frame is the one
/// length-form value with no payload to misframe.
pub(super) fn validate_link_length_form(
    name: &str,
    ether_type: u16,
    covered_payload_len: usize,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    if ether_type > MAX_FRAME_LENGTH
        || (ether_type == 0 && covered_payload_len == 0)
        || context
            .child
            .is_some_and(|child| binding_protocol(child).as_str() == "llc")
    {
        return Ok(());
    }
    strict_or_diagnostic(
        name,
        "build.link_length_form",
        "ether_type",
        format!(
            "ether_type {ether_type} is an 802.3 payload length and dissects as LLC framing; only an llc child can follow it"
        ),
        context,
        diagnostics,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ethernet {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ether_type: WireValue<u16>,
}

impl Default for Ethernet {
    fn default() -> Self {
        Self {
            destination: [0; 6],
            source: [0; 6],
            ether_type: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn ethernet_schema() => { protocol: protocol("ethernet"), name: "Ethernet II" }
    impl Ethernet {
        "destination" => { kind: Mac, derived: false, required: true, description: "Destination MAC address", reflect: destination, layout: (0, 6) },
        "source" => { kind: Mac, derived: false, required: true, description: "Source MAC address", reflect: source, layout: (6, 12) },
        "ether_type" => { kind: Unsigned, derived: true, required: false, description: "EtherType discriminator", reflect: ether_type, layout: (12, 14) },
    }
    layout pub(crate) fn ethernet_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EthernetCodec;

impl LayerCodec for EthernetCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ethernet")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Ethernet>()
            .ok_or_else(|| wrong_layer("ethernet", layer))?;
        let covered_payload = payload_without_padding("ethernet", payload, context)?;
        let expectation = link_type_expectation(
            "ethernet",
            context,
            &layer.ether_type,
            covered_payload.len(),
        )?;
        let mut diagnostics = Vec::new();
        validate_auto_raw_discriminator(
            "ethernet",
            "ether_type",
            &layer.ether_type,
            context,
            &mut diagnostics,
        )?;
        let (ether_type, materialized_type) = resolve_u16(
            "ethernet",
            "ether_type",
            &layer.ether_type,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        validate_link_length_form(
            "ethernet",
            ether_type,
            covered_payload.len(),
            context,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "ethernet",
            u64::from(ether_type),
            context,
            &mut diagnostics,
        )?;
        let mut header = Vec::with_capacity(ETHERNET_LEN);
        header.extend_from_slice(&layer.destination);
        header.extend_from_slice(&layer.source);
        header.extend_from_slice(&ether_type.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.ether_type = materialized_type;
        Ok(EncodedLayer {
            prefix: header,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: ethernet_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < ETHERNET_LEN {
            return Err(truncated("ethernet", ETHERNET_LEN, input.len()));
        }
        let mut destination = [0; 6];
        destination.copy_from_slice(&input[..6]);
        let mut source = [0; 6];
        source.copy_from_slice(&input[6..12]);
        let ether_type = u16::from_be_bytes([input[12], input[13]]);
        let (payload_len, next) = link_payload_selection(
            "ethernet",
            ether_type,
            input.len() - ETHERNET_LEN,
            ETHERNET_LEN,
        )?;
        Ok(DecodedLayerValue {
            layer: Box::new(Ethernet {
                destination,
                source,
                ether_type: WireValue::Exact(ether_type),
            }),
            consumed: ETHERNET_LEN,
            payload_len,
            next,
            fields: ethernet_layout(),
            diagnostics: Vec::new(),
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Ethernet::default(),
            &aliased_fields(
                "ethernet",
                fields,
                &[("dst", "destination"), ("src", "source")],
            )?,
        )
    }
}
