// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use crate::common::{
    expected_discriminator_for_value, invalid, make_layer, out_of_range, protocol, resolve_u16,
    truncated, validate_auto_raw_discriminator, validate_raw_child_discriminator, wrong_layer,
    wrong_type,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxSll {
    pub packet_type: u16,
    pub arp_hardware_type: u16,
    pub address_length: u16,
    pub address: [u8; 8],
    pub protocol: WireValue<u16>,
}

impl Default for LinuxSll {
    fn default() -> Self {
        Self {
            packet_type: 0,
            arp_hardware_type: 1,
            address_length: 6,
            address: [0; 8],
            protocol: WireValue::Auto,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxSll2 {
    pub protocol: WireValue<u16>,
    pub interface_index: u32,
    pub arp_hardware_type: u16,
    pub packet_type: u8,
    pub address_length: u8,
    pub address: [u8; 8],
}

impl Default for LinuxSll2 {
    fn default() -> Self {
        Self {
            protocol: WireValue::Auto,
            interface_index: 0,
            arp_hardware_type: 1,
            packet_type: 0,
            address_length: 6,
            address: [0; 8],
        }
    }
}

reflective_layer! {
    fn linux_sll_schema() => { protocol: protocol("linux_sll"), name: "Linux cooked capture v1" }
    impl LinuxSll {
        "protocol" => { kind: Unsigned, derived: true, required: false, description: "Protocol discriminator", get |layer| Some(reflect_get(&layer.protocol)), set |layer, value, name| reflect_set(&mut layer.protocol, linux_sll_schema(), name, value), layout: (14, 16) },
        "packet_type" => { kind: Unsigned, derived: false, required: true, description: "Packet direction/type", get |layer| Some(reflect_get(&layer.packet_type)), set |layer, value, name| reflect_set(&mut layer.packet_type, linux_sll_schema(), name, value), layout: (0, 2) },
        "arp_hardware_type" => { kind: Unsigned, derived: false, required: true, description: "ARP hardware type", get |layer| Some(reflect_get(&layer.arp_hardware_type)), set |layer, value, name| reflect_set(&mut layer.arp_hardware_type, linux_sll_schema(), name, value), layout: (2, 4) },
        "address_length" => { kind: Unsigned, derived: false, required: true, description: "Link address length", get |layer| Some(reflect_get(&layer.address_length)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.address_length = u16::try_from(value).ok().filter(|value| *value <= 8).ok_or_else(|| out_of_range(linux_sll_schema(), name))?; Ok(()) }, _ => Err(wrong_type(linux_sll_schema(), name, "unsigned")) }, layout: (4, 6) },
        "address" => { kind: Bytes, derived: false, required: false, description: "Eight-byte link address slot", get |layer| Some(reflect_get(&layer.address)), set |layer, value, name| reflect_set(&mut layer.address, linux_sll_schema(), name, value), layout: (6, 14) },
    }
    layout pub(crate) fn linux_sll_layout();
}

reflective_layer! {
    fn linux_sll2_schema() => { protocol: protocol("linux_sll2"), name: "Linux cooked capture v2" }
    impl LinuxSll2 {
        "protocol" => { kind: Unsigned, derived: true, required: false, description: "Protocol discriminator", get |layer| Some(reflect_get(&layer.protocol)), set |layer, value, name| reflect_set(&mut layer.protocol, linux_sll2_schema(), name, value), layout: (0, 2) },
        "packet_type" => { kind: Unsigned, derived: false, required: true, description: "Packet direction/type", get |layer| Some(reflect_get(&layer.packet_type)), set |layer, value, name| reflect_set(&mut layer.packet_type, linux_sll2_schema(), name, value), layout: (10, 11) },
        "arp_hardware_type" => { kind: Unsigned, derived: false, required: true, description: "ARP hardware type", get |layer| Some(reflect_get(&layer.arp_hardware_type)), set |layer, value, name| reflect_set(&mut layer.arp_hardware_type, linux_sll2_schema(), name, value), layout: (8, 10) },
        "interface_index" => { kind: Unsigned, derived: false, required: false, description: "Interface index", get |layer| Some(reflect_get(&layer.interface_index)), set |layer, value, name| reflect_set(&mut layer.interface_index, linux_sll2_schema(), name, value), layout: (4, 8) },
        "address_length" => { kind: Unsigned, derived: false, required: true, description: "Link address length", get |layer| Some(reflect_get(&layer.address_length)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.address_length = u8::try_from(value).ok().filter(|value| *value <= 8).ok_or_else(|| out_of_range(linux_sll2_schema(), name))?; Ok(()) }, _ => Err(wrong_type(linux_sll2_schema(), name, "unsigned")) }, layout: (11, 12) },
        "address" => { kind: Bytes, derived: false, required: false, description: "Eight-byte link address slot", get |layer| Some(reflect_get(&layer.address)), set |layer, value, name| reflect_set(&mut layer.address, linux_sll2_schema(), name, value), layout: (12, 20) },
    }
    layout pub(crate) fn linux_sll2_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LinuxSllCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LinuxSll2Codec;

impl LayerCodec for LinuxSllCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("linux_sll")
    }

    fn aliases(&self) -> &'static [&'static str] {
        crate::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<LinuxSll>()
            .ok_or_else(|| wrong_layer("linux_sll", layer))?;
        if layer.address_length > 8 {
            return Err(invalid("linux_sll", "address length exceeds slot"));
        }
        let mut diagnostics = Vec::new();
        let expectation =
            expected_discriminator_for_value("linux_sll", context, 0_u16, &layer.protocol);
        validate_auto_raw_discriminator(
            "linux_sll",
            "protocol",
            &layer.protocol,
            context,
            &mut diagnostics,
        )?;
        let (protocol_value, materialized_protocol) = resolve_u16(
            "linux_sll",
            "protocol",
            &layer.protocol,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "linux_sll",
            u64::from(protocol_value),
            context,
            &mut diagnostics,
        )?;
        let mut prefix = Vec::with_capacity(16);
        prefix.extend_from_slice(&layer.packet_type.to_be_bytes());
        prefix.extend_from_slice(&layer.arp_hardware_type.to_be_bytes());
        prefix.extend_from_slice(&layer.address_length.to_be_bytes());
        prefix.extend_from_slice(&layer.address);
        prefix.extend_from_slice(&protocol_value.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.protocol = materialized_protocol;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: linux_sll_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 16 {
            return Err(truncated("linux_sll", 16, input.len()));
        }
        let address_length = u16::from_be_bytes([input[4], input[5]]);
        if address_length > 8 {
            return Err(invalid("linux_sll", "address length exceeds slot"));
        }
        let mut address = [0; 8];
        address.copy_from_slice(&input[6..14]);
        let protocol_value = u16::from_be_bytes([input[14], input[15]]);
        Ok(DecodedLayerValue {
            layer: Box::new(LinuxSll {
                packet_type: u16::from_be_bytes([input[0], input[1]]),
                arp_hardware_type: u16::from_be_bytes([input[2], input[3]]),
                address_length,
                address,
                protocol: WireValue::Exact(protocol_value),
            }),
            consumed: 16,
            payload_offset: 16,
            payload_len: input.len() - 16,
            next: vec![Discriminator(protocol_value.into())],
            fields: linux_sll_layout(),
            diagnostics: Vec::new(),
            stop: input.len() == 16,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(LinuxSll::default(), fields)
    }
}

impl LayerCodec for LinuxSll2Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("linux_sll2")
    }

    fn aliases(&self) -> &'static [&'static str] {
        crate::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<LinuxSll2>()
            .ok_or_else(|| wrong_layer("linux_sll2", layer))?;
        if layer.address_length > 8 {
            return Err(invalid("linux_sll2", "address length exceeds slot"));
        }
        let mut diagnostics = Vec::new();
        let expectation =
            expected_discriminator_for_value("linux_sll2", context, 0_u16, &layer.protocol);
        validate_auto_raw_discriminator(
            "linux_sll2",
            "protocol",
            &layer.protocol,
            context,
            &mut diagnostics,
        )?;
        let (protocol_value, materialized_protocol) = resolve_u16(
            "linux_sll2",
            "protocol",
            &layer.protocol,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "linux_sll2",
            u64::from(protocol_value),
            context,
            &mut diagnostics,
        )?;
        let mut prefix = Vec::with_capacity(20);
        prefix.extend_from_slice(&protocol_value.to_be_bytes());
        prefix.extend_from_slice(&[0, 0]);
        prefix.extend_from_slice(&layer.interface_index.to_be_bytes());
        prefix.extend_from_slice(&layer.arp_hardware_type.to_be_bytes());
        prefix.push(layer.packet_type);
        prefix.push(layer.address_length);
        prefix.extend_from_slice(&layer.address);
        let mut materialized = layer.clone();
        materialized.protocol = materialized_protocol;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: linux_sll2_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 20 {
            return Err(truncated("linux_sll2", 20, input.len()));
        }
        if input[2] != 0 || input[3] != 0 {
            return Err(invalid("linux_sll2", "reserved field is non-zero"));
        }
        if input[11] > 8 {
            return Err(invalid("linux_sll2", "address length exceeds slot"));
        }
        let protocol_value = u16::from_be_bytes([input[0], input[1]]);
        let mut address = [0; 8];
        address.copy_from_slice(&input[12..20]);
        Ok(DecodedLayerValue {
            layer: Box::new(LinuxSll2 {
                protocol: WireValue::Exact(protocol_value),
                interface_index: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                arp_hardware_type: u16::from_be_bytes([input[8], input[9]]),
                packet_type: input[10],
                address_length: input[11],
                address,
            }),
            consumed: 20,
            payload_offset: 20,
            payload_len: input.len() - 20,
            next: vec![Discriminator(protocol_value.into())],
            fields: linux_sll2_layout(),
            diagnostics: Vec::new(),
            stop: input.len() == 20,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(LinuxSll2::default(), fields)
    }
}
