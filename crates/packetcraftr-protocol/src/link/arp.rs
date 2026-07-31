// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! ARP message model and codec.
//!
//! This is a wire-format encoder and decoder only. It models the header fields
//! so ARP frames can be built for tests and dissected out of captures; it
//! performs no address resolution, caching, or announcement of its own.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
};

use super::super::common::{
    ValueExpectation, aliased_fields, make_layer, protocol, resolve_u8, truncated, wrong_layer,
};

const ARP_ETHERNET_IPV4_LEN: usize = 28;

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
    }
    layout pub(crate) fn arp_layout();
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
            if context.mode == packetcraftr_packet::build::BuildMode::Strict {
                return Err(CodecError::Unsupported {
                    protocol: protocol("arp"),
                    message,
                });
            }
            diagnostics.push(
                packetcraftr_packet::diagnostic::Diagnostic::warning(
                    "build.arp_address_types",
                    message,
                )
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
