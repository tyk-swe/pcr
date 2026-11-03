// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::common::{truncated, typed_layer};
use bytes::Bytes;

use crate::{
    codec::{Codec, DecodeContext, Decoded, EncodeContext, Encoded},
    field::WireValue,
    layer::{Id, Layer, reflective_layer},
};

use super::ether_type::{link_payload_selection, resolve_ether_type};
use crate::protocol::headers::EthernetHeader;

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Ethernet.as_str();

const ETHERNET_LEN: usize = EthernetHeader::LENGTH;

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
    fn ethernet_schema() => { protocol: Id::new(NAME), name: "Ethernet II" }
    impl Ethernet {
        "destination" | "dst" => { kind: Mac, derived: false, required: true, description: "Destination MAC address", reflect: destination, layout: (0, 6) },
        "source" | "src" => { kind: Mac, derived: false, required: true, description: "Source MAC address", reflect: source, layout: (6, 12) },
        "ether_type" => { kind: Unsigned, derived: true, required: false, description: "EtherType discriminator", reflect: ether_type, layout: (12, 14) },
    }
    layout pub(crate) fn ethernet_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EthernetCodec;

impl Codec for EthernetCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &ethernet_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &EncodeContext<'_>,
    ) -> Result<Encoded, crate::codec::Error> {
        let layer = typed_layer::<Ethernet>(NAME, layer)?;
        let (ether_type, materialized_type, diagnostics) =
            resolve_ether_type(NAME, &layer.ether_type, payload, context)?;
        let mut header = Vec::with_capacity(ETHERNET_LEN);
        header.extend_from_slice(&layer.destination);
        header.extend_from_slice(&layer.source);
        header.extend_from_slice(&ether_type.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.ether_type = materialized_type;
        Ok(Encoded::header(header, Box::new(materialized))
            .with_fields(ethernet_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &DecodeContext<'_>,
    ) -> Result<Decoded, crate::codec::Error> {
        let Ok((destination, source, ether_type)) = EthernetHeader::base(&input) else {
            return Err(truncated(NAME, ETHERNET_LEN, input.len()));
        };
        let (destination, source) = (destination.0, source.0);
        let (payload_len, next) = link_payload_selection(
            NAME,
            ether_type,
            input.len().saturating_sub(ETHERNET_LEN),
            ETHERNET_LEN,
        )?;
        Ok(Decoded {
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

    fn schema(&self) -> Option<&'static crate::layer::Schema> {
        Some(ethernet_schema())
    }

    fn new_layer(&self) -> Result<Box<dyn Layer>, crate::codec::Error> {
        Ok(Box::new(Ethernet::default()))
    }
}
