// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::DocumentError;
use super::types::{LayerDocument, PACKET_DOCUMENT_SCHEMA_V1, PacketDocument};
use crate::Packet;
use crate::registry::{CodecError, ProtocolRegistry};

impl PacketDocument {
    pub fn from_packet(packet: &Packet) -> Self {
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
                LayerDocument {
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
        registry: &ProtocolRegistry,
        max_layers: usize,
    ) -> Result<Packet, DocumentError> {
        self.validate_schema()?;
        if self.layers.len() > max_layers {
            return Err(DocumentError::LayerLimit { limit: max_layers });
        }
        let mut packet = Packet::with_capacity(self.layers.len());
        for (index, layer) in self.layers.iter().enumerate() {
            let codec = registry.codec_named(&layer.protocol).ok_or_else(|| {
                DocumentError::UnknownProtocol {
                    layer: index,
                    protocol: layer.protocol.clone(),
                }
            })?;
            let value = codec
                .make_layer(&layer.fields)
                .map_err(|source| DocumentError::Layer {
                    layer: index,
                    protocol: layer.protocol.clone(),
                    source,
                })?;
            value
                .validate_required_fields()
                .map_err(|source| DocumentError::Layer {
                    layer: index,
                    protocol: layer.protocol.clone(),
                    source: CodecError::Field(source),
                })?;
            packet.push_boxed(value);
        }
        Ok(packet)
    }
}
