// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::Error;
use super::types::{Layer, PACKET_DOCUMENT_SCHEMA_V1, Packet};

use crate::registry::Registry;

impl Packet {
    pub fn from_packet(packet: &crate::Packet) -> Self {
        let layers = packet
            .iter()
            .map(|layer| {
                let fields = layer
                    .schema()
                    .fields
                    .iter()
                    .filter_map(|field| {
                        layer
                            .field(field.name)
                            .map(|value| (field.name.to_owned(), value))
                    })
                    .collect();
                Layer {
                    protocol: layer.protocol_id().to_string(),
                    fields,
                }
            })
            .collect();
        Self {
            schema: PACKET_DOCUMENT_SCHEMA_V1.to_owned(),
            layers,
        }
    }

    pub fn to_packet(
        &self,
        registry: &Registry,
        max_layers: usize,
    ) -> Result<crate::Packet, Error> {
        if self.schema == super::v2::PACKET_DOCUMENT_SCHEMA_V2 {
            let v2_doc = super::v2::Document {
                layers: self
                    .layers
                    .iter()
                    .map(|l| super::v2::Layer {
                        protocol: l.protocol.clone(),
                        fields: l
                            .fields
                            .iter()
                            .map(|(k, v)| {
                                (
                                    k.clone(),
                                    match v {
                                        crate::field::FieldValue::Text(t) => {
                                            super::v2::Value::Scalar(t.clone())
                                        }
                                        other => {
                                            super::v2::Value::Scalar(crate::field::text_form(other))
                                        }
                                    },
                                )
                            })
                            .collect(),
                    })
                    .collect(),
            };
            return v2_doc.to_packet(registry, max_layers);
        }
        self.validate_schema()?;
        if self.layers.len() > max_layers {
            return Err(Error::LayerLimit { limit: max_layers });
        }
        let mut packet = crate::Packet::with_capacity(self.layers.len());
        for (index, layer) in self.layers.iter().enumerate() {
            let codec =
                registry
                    .codec_named(&layer.protocol)
                    .ok_or_else(|| Error::UnknownProtocol {
                        layer: index,
                        protocol: layer.protocol.clone(),
                    })?;
            let value = codec
                .make_layer(&layer.fields)
                .map_err(|source| Error::Layer {
                    layer: index,
                    protocol: layer.protocol.clone(),
                    source,
                })?;
            value
                .validate_required_fields()
                .map_err(|source| Error::Layer {
                    layer: index,
                    protocol: layer.protocol.clone(),
                    source: crate::codec::Error::Field(source),
                })?;
            packet.push_boxed(value);
        }
        Ok(packet)
    }
}
