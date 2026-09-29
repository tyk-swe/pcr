// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
};

use super::ether_type::{link_payload_selection, resolve_ether_type};
use crate::protocol::common::{make_layer, protocol, truncated, typed_layer};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Ethernet.as_str();

const ETHERNET_LEN: usize = 14;
const MAC_LEN: usize = 6;

fn ethernet_chunk<const N: usize>(input: &[u8], offset: usize) -> Option<[u8; N]> {
    input
        .get(offset..)
        .and_then(<[u8]>::first_chunk::<N>)
        .copied()
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
    fn ethernet_schema() => { protocol: protocol(NAME), name: "Ethernet II" }
    impl Ethernet {
        "destination" | "dst" => { kind: Mac, derived: false, required: true, description: "Destination MAC address", reflect: destination, layout: (0, 6) },
        "source" | "src" => { kind: Mac, derived: false, required: true, description: "Source MAC address", reflect: source, layout: (6, 12) },
        "ether_type" => { kind: Unsigned, derived: true, required: false, description: "EtherType discriminator", reflect: ether_type, layout: (12, 14) },
    }
    layout pub(crate) fn ethernet_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EthernetCodec;

impl LayerCodec for EthernetCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &ethernet_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Ethernet>(NAME, layer)?;
        let (ether_type, materialized_type, diagnostics) =
            resolve_ether_type(NAME, &layer.ether_type, payload, context)?;
        let mut header = Vec::with_capacity(ETHERNET_LEN);
        header.extend_from_slice(&layer.destination);
        header.extend_from_slice(&layer.source);
        header.extend_from_slice(&ether_type.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.ether_type = materialized_type;
        Ok(EncodedLayer::header(header, Box::new(materialized))
            .with_fields(ethernet_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let (Some(destination), Some(source), Some(ether_type)) = (
            ethernet_chunk::<MAC_LEN>(&input, 0),
            ethernet_chunk::<MAC_LEN>(&input, MAC_LEN),
            ethernet_chunk::<2>(&input, 12),
        ) else {
            return Err(truncated(NAME, ETHERNET_LEN, input.len()));
        };
        let ether_type = u16::from_be_bytes(ether_type);
        let (payload_len, next) = link_payload_selection(
            NAME,
            ether_type,
            input.len().saturating_sub(ETHERNET_LEN),
            ETHERNET_LEN,
        )?;
        Ok(DecodedLayer {
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Ethernet::default(), fields)
    }
}
