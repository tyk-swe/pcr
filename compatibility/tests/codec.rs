// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use packetcraftr_core::{
    Packet, build,
    codec::*,
    decode,
    field::FieldValue,
    frame::{Frame, LinkType},
    layer::{Id, Layer},
    reflective_layer, registry,
};
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Marker {
    value: u8,
}
reflective_layer! {
    fn schema() => { protocol: Id::new("marker"), name: "Downstream marker" }
    impl Marker {
        "value" => { kind: Unsigned, derived: false, required: true,
            description: "One application-owned byte", reflect: value, layout: (0, 1) }
    }
    layout fn layout();
}
#[derive(Debug)]
struct MarkerCodec;
impl LayerCodec for MarkerCodec {
    fn protocol_id(&self) -> &'static Id {
        &schema().protocol
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        _: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, Error> {
        let marker = layer
            .as_any()
            .downcast_ref::<Marker>()
            .ok_or(Error::WrongLayer {
                expected: *self.protocol_id(),
                actual: *layer.protocol_id(),
            })?;
        if context.remaining_packet_bytes == 0 {
            return Err(Error::Invalid {
                protocol: *self.protocol_id(),
                message: "marker exceeds budget".to_owned(),
            });
        }
        Ok(
            EncodedLayer::header(vec![marker.value], Box::new(marker.clone()))
                .with_fields(layout()),
        )
    }
    fn decode(&self, input: &[u8], _: &LayerDecodeContext<'_>) -> Result<DecodedLayer, Error> {
        let value = *input.first().ok_or(Error::Truncated {
            protocol: *self.protocol_id(),
            needed: 1,
            available: 0,
        })?;
        let mut result = DecodedLayer::terminal(Box::new(Marker { value }), 1);
        result.fields = layout();
        Ok(result)
    }
    fn make_layer(&self, fields: &BTreeMap<String, FieldValue>) -> Result<Box<dyn Layer>, Error> {
        let mut marker = Marker::default();
        for (name, value) in fields {
            marker.set_field(name, value.clone())?;
        }
        Ok(Box::new(marker))
    }
}
#[test]
fn downstream_codec_registers_builds_and_decodes() {
    let mut registry = registry::Builder::new();
    registry.register_codec(MarkerCodec, &["m"]).unwrap();
    registry.bind_link_type(777, "marker").unwrap();
    let registry = Arc::new(registry.build().unwrap());
    let mut packet = Packet::new();
    packet.push(Marker { value: 42 });
    let built = build::Builder::new(registry.clone())
        .build(packet, build::Context::default(), build::Options::default())
        .unwrap();
    assert_eq!(built.bytes.as_ref(), [42]);
    let decoded = decode::Dissector::new(registry)
        .decode(
            Frame::new(SystemTime::UNIX_EPOCH, LinkType(777), built.bytes).unwrap(),
            decode::Options::default(),
        )
        .unwrap();
    assert_eq!(decoded.packet.get::<Marker>().unwrap().value, 42);
}
