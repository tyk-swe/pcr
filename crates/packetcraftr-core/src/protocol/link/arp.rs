// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! ARP message model and codec.
//!
//! This is a wire-format encoder and decoder only. It models the header fields
//! so ARP frames can be built and dissected out of captures; it performs no
//! address resolution, caching, or announcement of its own.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
};

use crate::protocol::common::{
    ValueExpectation, make_layer, protocol, resolve_u8, truncated, typed_layer,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Arp.as_str();

const ARP_ETHERNET_IPV4_LEN: usize = 28;
/// The fixed head that names the address families and their lengths.
const ARP_HEAD_LEN: usize = 8;

/// Reads the fixed-size chunk of `input` that starts at `offset`.
fn arp_chunk<const N: usize>(input: &[u8], offset: usize) -> Option<[u8; N]> {
    input
        .get(offset..)
        .and_then(<[u8]>::first_chunk::<N>)
        .copied()
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
    fn arp_schema() => { protocol: protocol(NAME), name: "ARP" }
    impl Arp {
        "hardware_type" => { kind: Unsigned, derived: false, required: true, description: "Hardware address family", reflect: hardware_type, layout: (0, 2) },
        "protocol_type" => { kind: Unsigned, derived: false, required: true, description: "Protocol address family", reflect: protocol_type, layout: (2, 4) },
        "hardware_len" => { kind: Unsigned, derived: true, required: false, description: "Hardware address length", reflect: hardware_len, layout: (4, 5) },
        "protocol_len" => { kind: Unsigned, derived: true, required: false, description: "Protocol address length", reflect: protocol_len, layout: (5, 6) },
        "operation" | "op" => { kind: Unsigned, derived: false, required: true, description: "ARP operation", reflect: operation, layout: (6, 8) },
        "sender_hardware" | "sha" => { kind: Mac, derived: false, required: true, description: "Sender hardware address", reflect: sender_hardware, layout: (8, 14) },
        "sender_protocol" | "spa" => { kind: Ipv4, derived: false, required: true, description: "Sender IPv4 address", reflect: sender_protocol, layout: (14, 18) },
        "target_hardware" | "tha" => { kind: Mac, derived: false, required: true, description: "Target hardware address", reflect: target_hardware, layout: (18, 24) },
        "target_protocol" | "tpa" => { kind: Ipv4, derived: false, required: true, description: "Target IPv4 address", reflect: target_protocol, layout: (24, 28) },
    }
    layout pub(crate) fn arp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ArpCodec;

impl LayerCodec for ArpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &arp_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Arp>(NAME, layer)?;
        let mut diagnostics = Vec::new();
        if layer.hardware_type != 1 || layer.protocol_type != 0x0800 {
            let message = format!(
                "typed ARP requires Ethernet/IPv4 types (htype={}, ptype=0x{:04x})",
                layer.hardware_type, layer.protocol_type
            );
            if context.mode == crate::codec::Mode::Strict {
                return Err(crate::codec::Error::Unsupported {
                    protocol: protocol(NAME),
                    message,
                });
            }
            diagnostics.push(
                crate::diagnostic::Diagnostic::warning("build.arp_address_types", message)
                    .at_field("hardware_type"),
            );
        }
        let (hardware_len, materialized_hardware_len) = resolve_u8(
            NAME,
            "hardware_len",
            &layer.hardware_len,
            ValueExpectation::Required(6),
            context.mode,
            &mut diagnostics,
        )?;
        let (protocol_len, materialized_protocol_len) = resolve_u8(
            NAME,
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
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(arp_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(head) = input.first_chunk::<ARP_HEAD_LEN>() else {
            return Err(truncated(NAME, ARP_HEAD_LEN, input.len()));
        };
        let hardware_len = head[4];
        let protocol_len = head[5];
        let hardware_type = u16::from_be_bytes([head[0], head[1]]);
        let protocol_type = u16::from_be_bytes([head[2], head[3]]);
        if hardware_type != 1 || protocol_type != 0x0800 || hardware_len != 6 || protocol_len != 4 {
            return Err(crate::codec::Error::Unsupported {
                protocol: protocol(NAME),
                message: format!(
                    "only Ethernet/IPv4 ARP is typed (htype={hardware_type}, ptype=0x{protocol_type:04x}, hlen={hardware_len}, plen={protocol_len})"
                ),
            });
        }
        let (
            Some(sender_hardware),
            Some(sender_protocol),
            Some(target_hardware),
            Some(target_protocol),
        ) = (
            arp_chunk::<6>(input, 8),
            arp_chunk::<4>(input, 14),
            arp_chunk::<6>(input, 18),
            arp_chunk::<4>(input, 24),
        )
        else {
            return Err(truncated(NAME, ARP_ETHERNET_IPV4_LEN, input.len()));
        };
        let layer = Arp {
            hardware_type,
            protocol_type,
            hardware_len: WireValue::Exact(hardware_len),
            protocol_len: WireValue::Exact(protocol_len),
            operation: u16::from_be_bytes([head[6], head[7]]),
            sender_hardware,
            sender_protocol: Ipv4Addr::from(sender_protocol),
            target_hardware,
            target_protocol: Ipv4Addr::from(target_protocol),
        };
        Ok(DecodedLayer {
            layer: Box::new(layer),
            consumed: ARP_ETHERNET_IPV4_LEN,
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Arp::default(), fields)
    }
}
