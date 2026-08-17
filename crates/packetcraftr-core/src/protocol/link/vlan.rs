// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IEEE 802.1Q and 802.1ad VLAN tag models and codecs.

use std::collections::BTreeMap;

use crate::{
    codec::{
        DecodedLayerValue, EncodedLayer, Error as CodecError, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Id as ProtocolId, Layer, reflective_layer},
};

use super::super::common::{
    aliased_fields, invalid, make_layer, payload_without_padding, protocol, resolve_u16, truncated,
    validate_auto_raw_discriminator, validate_raw_child_discriminator, wrong_layer,
};
use super::ethernet::{link_payload_selection, link_type_expectation, validate_link_length_form};

const VLAN_LEN: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vlan {
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
    pub ether_type: WireValue<u16>,
}

impl Default for Vlan {
    fn default() -> Self {
        Self {
            priority: 0,
            drop_eligible: false,
            vlan_id: 1,
            ether_type: WireValue::Auto,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vlan8021ad {
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
    pub ether_type: WireValue<u16>,
}

impl Default for Vlan8021ad {
    fn default() -> Self {
        Self {
            priority: 0,
            drop_eligible: false,
            vlan_id: 1,
            ether_type: WireValue::Auto,
        }
    }
}

macro_rules! declare_vlan_layer {
    ($ty:ty, $schema:ident, $protocol:literal, $name:literal, $layout:ident) => {
        reflective_layer! {
            fn $schema() => { protocol: protocol($protocol), name: $name }
            impl $ty {
                "priority" => { kind: Unsigned, derived: false, required: false, description: "IEEE 802.1 priority code point", reflect_bounded: priority, 7_u64, layout: (0, 2) },
                "drop_eligible" => { kind: Bool, derived: false, required: false, description: "Drop eligible indicator", reflect: drop_eligible, layout: (0, 2) },
                "vlan_id" => { kind: Unsigned, derived: false, required: true, description: "VLAN identifier", reflect_bounded: vlan_id, 4095_u64, layout: (0, 2) },
                "ether_type" => { kind: Unsigned, derived: true, required: false, description: "Encapsulated EtherType", reflect: ether_type, layout: (2, 4) },
            }
            layout pub(crate) fn $layout();
        }
    };
}

declare_vlan_layer!(Vlan, vlan_schema, "vlan", "IEEE 802.1Q VLAN", vlan_layout);
declare_vlan_layer!(
    Vlan8021ad,
    vlan_ad_schema,
    "vlan8021ad",
    "IEEE 802.1ad Service VLAN",
    vlan_ad_layout
);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct VlanCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Vlan8021adCodec;

struct VlanEncodeFields<'a> {
    priority: u8,
    drop_eligible: bool,
    vlan_id: u16,
    ether_type: &'a WireValue<u16>,
}

fn encode_vlan<L>(
    name: &str,
    fields: VlanEncodeFields<'_>,
    payload: &[u8],
    context: &LayerEncodeContext<'_>,
    layout: fn() -> Vec<crate::layout::FieldLayout>,
    materialize: impl FnOnce(WireValue<u16>) -> L,
) -> Result<EncodedLayer, CodecError>
where
    L: Layer + Clone + 'static,
{
    if fields.priority > 7 || fields.vlan_id > 4095 {
        return Err(invalid(
            name,
            "VLAN priority or identifier is outside its wire range",
        ));
    }
    let covered_payload = payload_without_padding(name, payload, context)?;
    let expectation =
        link_type_expectation(name, context, fields.ether_type, covered_payload.len())?;
    let mut diagnostics = Vec::new();
    validate_auto_raw_discriminator(
        name,
        "ether_type",
        fields.ether_type,
        context,
        &mut diagnostics,
    )?;
    let (ether_type, materialized_type) = resolve_u16(
        name,
        "ether_type",
        fields.ether_type,
        expectation,
        context.mode,
        &mut diagnostics,
    )?;
    validate_link_length_form(
        name,
        ether_type,
        covered_payload.len(),
        context,
        &mut diagnostics,
    )?;
    validate_raw_child_discriminator(name, u64::from(ether_type), context, &mut diagnostics)?;
    let tci = (u16::from(fields.priority) << 13)
        | (if fields.drop_eligible { 1 << 12 } else { 0 })
        | (fields.vlan_id & 0x0fff);
    let mut prefix = Vec::with_capacity(VLAN_LEN);
    prefix.extend_from_slice(&tci.to_be_bytes());
    prefix.extend_from_slice(&ether_type.to_be_bytes());
    Ok(EncodedLayer {
        prefix,
        suffix: Vec::new(),
        materialized: Box::new(materialize(materialized_type)),
        fields: layout(),
        diagnostics,
    })
}

fn decode_vlan(
    name: &str,
    input: &[u8],
    layout: fn() -> Vec<crate::layout::FieldLayout>,
    layer: impl FnOnce(u8, bool, u16, WireValue<u16>) -> Box<dyn Layer>,
) -> Result<DecodedLayerValue, CodecError> {
    if input.len() < VLAN_LEN {
        return Err(truncated(name, VLAN_LEN, input.len()));
    }
    let tci = u16::from_be_bytes([input[0], input[1]]);
    let ether_type = u16::from_be_bytes([input[2], input[3]]);
    let (payload_len, next) =
        link_payload_selection(name, ether_type, input.len() - VLAN_LEN, VLAN_LEN)?;
    Ok(DecodedLayerValue {
        layer: layer(
            ((tci >> 13) & 7) as u8,
            (tci & 0x1000) != 0,
            tci & 0x0fff,
            WireValue::Exact(ether_type),
        ),
        consumed: VLAN_LEN,
        payload_len,
        next,
        fields: layout(),
        diagnostics: Vec::new(),
        stop: payload_len == 0,
        network: None,
    })
}

impl LayerCodec for VlanCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("vlan")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Vlan>()
            .ok_or_else(|| wrong_layer("vlan", layer))?;
        encode_vlan(
            "vlan",
            VlanEncodeFields {
                priority: layer.priority,
                drop_eligible: layer.drop_eligible,
                vlan_id: layer.vlan_id,
                ether_type: &layer.ether_type,
            },
            payload,
            context,
            vlan_layout,
            |ether_type| Vlan {
                ether_type,
                ..layer.clone()
            },
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_vlan(
            "vlan",
            input,
            vlan_layout,
            |priority, drop_eligible, vlan_id, ether_type| {
                Box::new(Vlan {
                    priority,
                    drop_eligible,
                    vlan_id,
                    ether_type,
                })
            },
        )
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Vlan::default(),
            &aliased_fields(
                "vlan",
                fields,
                &[
                    ("vid", "vlan_id"),
                    ("pcp", "priority"),
                    ("dei", "drop_eligible"),
                ],
            )?,
        )
    }
}

impl LayerCodec for Vlan8021adCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("vlan8021ad")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Vlan8021ad>()
            .ok_or_else(|| wrong_layer("vlan8021ad", layer))?;
        encode_vlan(
            "vlan8021ad",
            VlanEncodeFields {
                priority: layer.priority,
                drop_eligible: layer.drop_eligible,
                vlan_id: layer.vlan_id,
                ether_type: &layer.ether_type,
            },
            payload,
            context,
            vlan_ad_layout,
            |ether_type| Vlan8021ad {
                ether_type,
                ..layer.clone()
            },
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_vlan(
            "vlan8021ad",
            input,
            vlan_ad_layout,
            |priority, drop_eligible, vlan_id, ether_type| {
                Box::new(Vlan8021ad {
                    priority,
                    drop_eligible,
                    vlan_id,
                    ether_type,
                })
            },
        )
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Vlan8021ad::default(),
            &aliased_fields(
                "vlan8021ad",
                fields,
                &[
                    ("vid", "vlan_id"),
                    ("pcp", "priority"),
                    ("dei", "drop_eligible"),
                ],
            )?,
        )
    }
}
