// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IEEE 802.1Q and 802.1ad VLAN tag models and codecs.

use packetcraftr_packet::{
    codec::Discriminator,
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, NativeLayerCodec, NativeLayerDecodeContext,
        NativeLayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, reflect_get, reflect_set, reflective_layer},
};

use super::super::common::{
    expected_discriminator, invalid, make_layer, out_of_range, protocol, resolve_u16, truncated,
    validate_auto_raw_discriminator, validate_raw_child_discriminator, wrong_layer, wrong_type,
};

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
    ($ty:ty, $schema:ident, $protocol:literal, $name:literal, [$($alias:literal),*], $layout:ident) => {
        reflective_layer! {
            fn $schema() => { protocol: protocol($protocol), name: $name, aliases: [$($alias),*] }
            impl $ty {
                "priority" | "pcp" => { id: "priority", kind: Unsigned, derived: false, required: false, description: "IEEE 802.1 priority code point", get |layer| Some(reflect_get(&layer.priority)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.priority = u8::try_from(value).ok().filter(|value| *value <= 7).ok_or_else(|| out_of_range($schema(), name))?; Ok(()) }, _ => Err(wrong_type($schema(), name, "unsigned")) }, layout: (0, 2) },
                "drop_eligible" | "dei" => { id: "drop_eligible", kind: Bool, derived: false, required: false, description: "Drop eligible indicator", get |layer| Some(reflect_get(&layer.drop_eligible)), set |layer, value, name| reflect_set(&mut layer.drop_eligible, $schema(), name, value), layout: (0, 2) },
                "vlan_id" | "vid" => { id: "vlan_id", kind: Unsigned, derived: false, required: true, description: "VLAN identifier", get |layer| Some(reflect_get(&layer.vlan_id)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.vlan_id = u16::try_from(value).ok().filter(|value| *value <= 4095).ok_or_else(|| out_of_range($schema(), name))?; Ok(()) }, _ => Err(wrong_type($schema(), name, "unsigned")) }, layout: (0, 2) },
                "ether_type" => { id: "ether_type", kind: Unsigned, derived: true, required: false, description: "Encapsulated EtherType", get |layer| Some(reflect_get(&layer.ether_type)), set |layer, value, name| reflect_set(&mut layer.ether_type, $schema(), name, value), layout: (2, 4) },
                normalize |layer| { layer.ether_type.normalize(); }
            }
            layout fn $layout();
        }
    };
}

declare_vlan_layer!(
    Vlan,
    vlan_schema,
    "vlan",
    "IEEE 802.1Q VLAN",
    ["dot1q", "8021q"],
    vlan_layout
);
declare_vlan_layer!(
    Vlan8021ad,
    vlan_ad_schema,
    "vlan8021ad",
    "IEEE 802.1ad Service VLAN",
    ["dot1ad", "8021ad", "qinq"],
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
    context: &NativeLayerEncodeContext<'_>,
    layout: fn() -> Vec<packetcraftr_packet::layout::FieldLayout>,
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
    let expectation = expected_discriminator(name, context, 0_u16);
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
    layout: fn() -> Vec<packetcraftr_packet::layout::FieldLayout>,
    layer: impl FnOnce(u8, bool, u16, WireValue<u16>) -> Box<dyn Layer>,
) -> Result<DecodedLayerValue, CodecError> {
    if input.len() < VLAN_LEN {
        return Err(truncated(name, VLAN_LEN, input.len()));
    }
    let tci = u16::from_be_bytes([input[0], input[1]]);
    let ether_type = u16::from_be_bytes([input[2], input[3]]);
    Ok(DecodedLayerValue {
        layer: layer(
            ((tci >> 13) & 7) as u8,
            (tci & 0x1000) != 0,
            tci & 0x0fff,
            WireValue::Exact(ether_type),
        ),
        consumed: VLAN_LEN,
        payload_offset: VLAN_LEN,
        payload_len: input.len() - VLAN_LEN,
        next: vec![Discriminator(u64::from(ether_type))],
        fields: layout(),
        diagnostics: Vec::new(),
        stop: input.len() == VLAN_LEN,
        network: None,
    })
}

impl NativeLayerCodec for VlanCodec {
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
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
        _context: &NativeLayerDecodeContext,
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
        fields: &packetcraftr_packet::layer::ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Vlan::default(), fields)
    }
}

impl NativeLayerCodec for Vlan8021adCodec {
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
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
        _context: &NativeLayerDecodeContext,
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
        fields: &packetcraftr_packet::layer::ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Vlan8021ad::default(), fields)
    }
}
