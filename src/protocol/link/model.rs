// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, aliased_fields, expected_discriminator, invalid, make_layer, out_of_range,
    protocol, resolve_u8, resolve_u16, truncated, validate_auto_raw_discriminator,
    validate_raw_child_discriminator, wrong_layer, wrong_type,
};

const ETHERNET_LEN: usize = 14;
const VLAN_LEN: usize = 4;
const ARP_ETHERNET_IPV4_LEN: usize = 28;

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
        "destination" => { kind: Mac, derived: false, required: true, description: "Destination MAC address", get |layer| Some(reflect_get(&layer.destination)), set |layer, value, name| reflect_set(&mut layer.destination, ethernet_schema(), name, value), layout: (0, 6) },
        "source" => { kind: Mac, derived: false, required: true, description: "Source MAC address", get |layer| Some(reflect_get(&layer.source)), set |layer, value, name| reflect_set(&mut layer.source, ethernet_schema(), name, value), layout: (6, 12) },
        "ether_type" => { kind: Unsigned, derived: true, required: false, description: "EtherType discriminator", get |layer| Some(reflect_get(&layer.ether_type)), set |layer, value, name| reflect_set(&mut layer.ether_type, ethernet_schema(), name, value), layout: (12, 14) },
        normalize |layer| { layer.ether_type.normalize(); }
    }
    layout fn ethernet_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EthernetCodec;

impl LayerCodec for EthernetCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ethernet")
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
            .downcast_ref::<Ethernet>()
            .ok_or_else(|| wrong_layer("ethernet", layer))?;
        let expectation = expected_discriminator("ethernet", context, 0_u16);
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
        Ok(DecodedLayerValue {
            layer: Box::new(Ethernet {
                destination,
                source,
                ether_type: WireValue::Exact(ether_type),
            }),
            consumed: ETHERNET_LEN,
            payload_offset: ETHERNET_LEN,
            payload_len: input.len() - ETHERNET_LEN,
            next: vec![Discriminator(u64::from(ether_type))],
            fields: ethernet_layout(),
            diagnostics: Vec::new(),
            stop: input.len() == ETHERNET_LEN,
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
                "priority" => { kind: Unsigned, derived: false, required: false, description: "IEEE 802.1 priority code point", get |layer| Some(reflect_get(&layer.priority)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.priority = u8::try_from(value).ok().filter(|value| *value <= 7).ok_or_else(|| out_of_range($schema(), name))?; Ok(()) }, _ => Err(wrong_type($schema(), name, "unsigned")) }, layout: (0, 2) },
                "drop_eligible" => { kind: Bool, derived: false, required: false, description: "Drop eligible indicator", get |layer| Some(reflect_get(&layer.drop_eligible)), set |layer, value, name| reflect_set(&mut layer.drop_eligible, $schema(), name, value), layout: (0, 2) },
                "vlan_id" => { kind: Unsigned, derived: false, required: true, description: "VLAN identifier", get |layer| Some(reflect_get(&layer.vlan_id)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.vlan_id = u16::try_from(value).ok().filter(|value| *value <= 4095).ok_or_else(|| out_of_range($schema(), name))?; Ok(()) }, _ => Err(wrong_type($schema(), name, "unsigned")) }, layout: (0, 2) },
                "ether_type" => { kind: Unsigned, derived: true, required: false, description: "Encapsulated EtherType", get |layer| Some(reflect_get(&layer.ether_type)), set |layer, value, name| reflect_set(&mut layer.ether_type, $schema(), name, value), layout: (2, 4) },
                normalize |layer| { layer.ether_type.normalize(); }
            }
            layout fn $layout();
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
    context: &LayerEncodeContext<'_>,
    layout: fn() -> Vec<crate::packet::layout::FieldLayout>,
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
    layout: fn() -> Vec<crate::packet::layout::FieldLayout>,
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

impl LayerCodec for VlanCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("vlan")
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arp {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: WireValue<u8>,
    pub protocol_len: WireValue<u8>,
    pub operation: u16,
    pub sender_hardware: [u8; 6],
    pub sender_protocol: Ipv4Addr,
    pub target_hardware: [u8; 6],
    pub target_protocol: Ipv4Addr,
}

impl Default for Arp {
    fn default() -> Self {
        Self {
            hardware_type: 1,
            protocol_type: 0x0800,
            hardware_len: WireValue::Auto,
            protocol_len: WireValue::Auto,
            operation: 1,
            sender_hardware: [0; 6],
            sender_protocol: Ipv4Addr::UNSPECIFIED,
            target_hardware: [0; 6],
            target_protocol: Ipv4Addr::UNSPECIFIED,
        }
    }
}

reflective_layer! {
    fn arp_schema() => { protocol: protocol("arp"), name: "ARP" }
    impl Arp {
        "hardware_type" => { kind: Unsigned, derived: false, required: true, description: "Hardware address family", get |layer| Some(reflect_get(&layer.hardware_type)), set |layer, value, name| reflect_set(&mut layer.hardware_type, arp_schema(), name, value), layout: (0, 2) },
        "protocol_type" => { kind: Unsigned, derived: false, required: true, description: "Protocol address family", get |layer| Some(reflect_get(&layer.protocol_type)), set |layer, value, name| reflect_set(&mut layer.protocol_type, arp_schema(), name, value), layout: (2, 4) },
        "hardware_len" => { kind: Unsigned, derived: true, required: false, description: "Hardware address length", get |layer| Some(reflect_get(&layer.hardware_len)), set |layer, value, name| reflect_set(&mut layer.hardware_len, arp_schema(), name, value), layout: (4, 5) },
        "protocol_len" => { kind: Unsigned, derived: true, required: false, description: "Protocol address length", get |layer| Some(reflect_get(&layer.protocol_len)), set |layer, value, name| reflect_set(&mut layer.protocol_len, arp_schema(), name, value), layout: (5, 6) },
        "operation" => { kind: Unsigned, derived: false, required: true, description: "ARP operation", get |layer| Some(reflect_get(&layer.operation)), set |layer, value, name| reflect_set(&mut layer.operation, arp_schema(), name, value), layout: (6, 8) },
        "sender_hardware" => { kind: Mac, derived: false, required: true, description: "Sender hardware address", get |layer| Some(reflect_get(&layer.sender_hardware)), set |layer, value, name| reflect_set(&mut layer.sender_hardware, arp_schema(), name, value), layout: (8, 14) },
        "sender_protocol" => { kind: Ipv4, derived: false, required: true, description: "Sender IPv4 address", get |layer| Some(reflect_get(&layer.sender_protocol)), set |layer, value, name| reflect_set(&mut layer.sender_protocol, arp_schema(), name, value), layout: (14, 18) },
        "target_hardware" => { kind: Mac, derived: false, required: true, description: "Target hardware address", get |layer| Some(reflect_get(&layer.target_hardware)), set |layer, value, name| reflect_set(&mut layer.target_hardware, arp_schema(), name, value), layout: (18, 24) },
        "target_protocol" => { kind: Ipv4, derived: false, required: true, description: "Target IPv4 address", get |layer| Some(reflect_get(&layer.target_protocol)), set |layer, value, name| reflect_set(&mut layer.target_protocol, arp_schema(), name, value), layout: (24, 28) },
        normalize |layer| { layer.hardware_len.normalize(); layer.protocol_len.normalize(); }
    }
    layout fn arp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ArpCodec;

impl LayerCodec for ArpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("arp")
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
            .downcast_ref::<Arp>()
            .ok_or_else(|| wrong_layer("arp", layer))?;
        let mut diagnostics = Vec::new();
        if layer.hardware_type != 1 || layer.protocol_type != 0x0800 {
            let message = format!(
                "typed ARP requires Ethernet/IPv4 types (htype={}, ptype=0x{:04x})",
                layer.hardware_type, layer.protocol_type
            );
            if context.mode == crate::packet::build::BuildMode::Strict {
                return Err(CodecError::Unsupported {
                    protocol: protocol("arp"),
                    message,
                });
            }
            diagnostics.push(
                crate::packet::diagnostic::Diagnostic::warning("build.arp_address_types", message)
                    .at_field("hardware_type"),
            );
        }
        let (hardware_len, materialized_hardware_len) = resolve_u8(
            "arp",
            "hardware_len",
            &layer.hardware_len,
            ValueExpectation::Required(6),
            context.mode,
            &mut diagnostics,
        )?;
        let (protocol_len, materialized_protocol_len) = resolve_u8(
            "arp",
            "protocol_len",
            &layer.protocol_len,
            ValueExpectation::Required(4),
            context.mode,
            &mut diagnostics,
        )?;
        let mut prefix = Vec::with_capacity(ARP_ETHERNET_IPV4_LEN);
        prefix.extend_from_slice(&layer.hardware_type.to_be_bytes());
        prefix.extend_from_slice(&layer.protocol_type.to_be_bytes());
        prefix.push(hardware_len);
        prefix.push(protocol_len);
        prefix.extend_from_slice(&layer.operation.to_be_bytes());
        prefix.extend_from_slice(&layer.sender_hardware);
        prefix.extend_from_slice(&layer.sender_protocol.octets());
        prefix.extend_from_slice(&layer.target_hardware);
        prefix.extend_from_slice(&layer.target_protocol.octets());
        let mut materialized = layer.clone();
        materialized.hardware_len = materialized_hardware_len;
        materialized.protocol_len = materialized_protocol_len;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: arp_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 8 {
            return Err(truncated("arp", 8, input.len()));
        }
        let hardware_len = input[4];
        let protocol_len = input[5];
        let hardware_type = u16::from_be_bytes([input[0], input[1]]);
        let protocol_type = u16::from_be_bytes([input[2], input[3]]);
        if hardware_type != 1 || protocol_type != 0x0800 || hardware_len != 6 || protocol_len != 4 {
            return Err(CodecError::Unsupported {
                protocol: protocol("arp"),
                message: format!(
                    "only Ethernet/IPv4 ARP is typed (htype={hardware_type}, ptype=0x{protocol_type:04x}, hlen={hardware_len}, plen={protocol_len})"
                ),
            });
        }
        if input.len() < ARP_ETHERNET_IPV4_LEN {
            return Err(truncated("arp", ARP_ETHERNET_IPV4_LEN, input.len()));
        }
        let mut sender_hardware = [0; 6];
        sender_hardware.copy_from_slice(&input[8..14]);
        let mut target_hardware = [0; 6];
        target_hardware.copy_from_slice(&input[18..24]);
        let layer = Arp {
            hardware_type,
            protocol_type,
            hardware_len: WireValue::Exact(hardware_len),
            protocol_len: WireValue::Exact(protocol_len),
            operation: u16::from_be_bytes([input[6], input[7]]),
            sender_hardware,
            sender_protocol: Ipv4Addr::new(input[14], input[15], input[16], input[17]),
            target_hardware,
            target_protocol: Ipv4Addr::new(input[24], input[25], input[26], input[27]),
        };
        Ok(DecodedLayerValue {
            layer: Box::new(layer),
            consumed: ARP_ETHERNET_IPV4_LEN,
            payload_offset: ARP_ETHERNET_IPV4_LEN,
            payload_len: 0,
            next: Vec::new(),
            fields: arp_layout(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Arp::default(),
            &aliased_fields(
                "arp",
                fields,
                &[
                    ("sha", "sender_hardware"),
                    ("spa", "sender_protocol"),
                    ("tha", "target_hardware"),
                    ("tpa", "target_protocol"),
                    ("op", "operation"),
                ],
            )?,
        )
    }
}
