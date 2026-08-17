// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::Error;
use super::types::{Layer, PACKET_DOCUMENT_SCHEMA_V1, Packet};
use crate::Packet as CorePacket;
use crate::codec::Error as CodecError;
use crate::registry::Registry;

impl Packet {
    pub fn from_packet(packet: &CorePacket) -> Self {
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

    pub fn to_packet(&self, registry: &Registry, max_layers: usize) -> Result<CorePacket, Error> {
        self.validate_schema()?;
        if self.layers.len() > max_layers {
            return Err(Error::LayerLimit { limit: max_layers });
        }
        let mut packet = CorePacket::with_capacity(self.layers.len());
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
                    source: CodecError::Field(source),
                })?;
            packet.push_boxed(value);
        }
        Ok(packet)
    }
}
