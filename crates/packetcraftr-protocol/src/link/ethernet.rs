// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ethernet II frame model and codec.

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

use super::super::common::{
    aliased_fields, expected_discriminator, make_layer, protocol, resolve_u16, truncated,
    validate_auto_raw_discriminator, validate_raw_child_discriminator, wrong_layer,
};

const ETHERNET_LEN: usize = 14;

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
    layout pub(crate) fn ethernet_layout();
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
