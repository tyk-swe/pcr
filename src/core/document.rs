// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::packet::Packet;
use super::registry::{CodecError, ProtocolRegistry};
use super::value::FieldValue;

pub const PACKET_DOCUMENT_SCHEMA_V1: &str = "packetcraftr.packet/v1";
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_DOCUMENT_NESTING: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentFormat {
    Json,
    Yaml,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketDocument {
    pub schema: String,
    pub layers: Vec<LayerDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerDocument {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, FieldValue>,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DocumentError {
    #[error("packet document has {actual} bytes, exceeding limit {limit}")]
    SizeLimit { actual: usize, limit: usize },
    #[error("could not parse {format} packet document: {message}")]
    Parse {
        format: &'static str,
        message: String,
    },
    #[error("unsupported packet document schema {actual}; expected {expected}")]
    Schema {
        actual: String,
        expected: &'static str,
    },
    #[error("packet document has more than {limit} layers")]
    LayerLimit { limit: usize },
    #[error("packet document field nesting exceeds configured limit {limit}")]
    NestingLimit { limit: usize },
    #[error("unknown protocol {protocol} at layer {layer}")]
    UnknownProtocol { layer: usize, protocol: String },
    #[error("invalid {protocol} layer at index {layer}: {source}")]
    Layer {
        layer: usize,
        protocol: String,
        #[source]
        source: CodecError,
    },
    #[error("could not serialize {format} packet document: {message}")]
    Serialize {
        format: &'static str,
        message: String,
    },
}

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

    pub fn parse(
        input: &str,
        format: DocumentFormat,
        max_bytes: usize,
    ) -> Result<Self, DocumentError> {
        Self::parse_with_limits(input, format, max_bytes, DEFAULT_MAX_DOCUMENT_NESTING)
    }

    pub fn parse_with_limits(
        input: &str,
        format: DocumentFormat,
        max_bytes: usize,
        max_nesting: usize,
    ) -> Result<Self, DocumentError> {
        if input.len() > max_bytes {
            return Err(DocumentError::SizeLimit {
                actual: input.len(),
                limit: max_bytes,
            });
        }
        let document = match format {
            DocumentFormat::Json => {
                serde_json::from_str(input).map_err(|source| DocumentError::Parse {
                    format: "JSON",
                    message: source.to_string(),
                })?
            }
            DocumentFormat::Yaml => {
                noyalib::compat::serde_yaml::from_str(input).map_err(|source| {
                    DocumentError::Parse {
                        format: "YAML",
                        message: source.to_string(),
                    }
                })?
            }
        };
        validate_value_nesting(&document, max_nesting)?;
        Ok(document)
    }

    pub fn validate_schema(&self) -> Result<(), DocumentError> {
        if self.schema != PACKET_DOCUMENT_SCHEMA_V1 {
            return Err(DocumentError::Schema {
                actual: self.schema.clone(),
                expected: PACKET_DOCUMENT_SCHEMA_V1,
            });
        }
        Ok(())
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
            packet.push_boxed(value);
        }
        Ok(packet)
    }

    pub fn to_json_pretty(&self) -> Result<String, DocumentError> {
        serde_json::to_string_pretty(self).map_err(|source| DocumentError::Serialize {
            format: "JSON",
            message: source.to_string(),
        })
    }

    pub fn to_yaml(&self) -> Result<String, DocumentError> {
        noyalib::compat::serde_yaml::to_string(self).map_err(|source| DocumentError::Serialize {
            format: "YAML",
            message: source.to_string(),
        })
    }
}

fn validate_value_nesting(document: &PacketDocument, maximum: usize) -> Result<(), DocumentError> {
    let mut pending = document
        .layers
        .iter()
        .flat_map(|layer| layer.fields.values().map(|value| (value, 0_usize)))
        .collect::<Vec<_>>();
    while let Some((value, depth)) = pending.pop() {
        let FieldValue::List(values) = value else {
            continue;
        };
        if depth >= maximum {
            return Err(DocumentError::NestingLimit { limit: maximum });
        }
        pending.extend(values.iter().map(|value| (value, depth + 1)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::core::Raw;

    #[test]
    fn yaml_byte_arrays_round_trip_like_json_byte_arrays() {
        let yaml = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        type: bytes
        value: [104, 101, 108, 108, 111]
"#;
        let document = PacketDocument::parse(yaml, DocumentFormat::Yaml, 4096).unwrap();
        let registry = crate::protocols::default_registry().unwrap();
        let packet = document.to_packet(&registry, 64).unwrap();

        assert_eq!(
            packet.get::<Raw>().unwrap().bytes,
            Bytes::from_static(b"hello")
        );
        assert!(document.to_yaml().unwrap().contains("- 104"));
    }

    #[test]
    fn document_field_nesting_is_configurable_and_bounded() {
        let json = r#"{
            "schema":"packetcraftr.packet/v1",
            "layers":[{"protocol":"raw","fields":{"bytes":{
                "type":"list","value":[{"type":"list","value":[{
                    "type":"list","value":[]
                }]}]
            }}}]
        }"#;

        assert!(matches!(
            PacketDocument::parse_with_limits(json, DocumentFormat::Json, 4096, 2),
            Err(DocumentError::NestingLimit { limit: 2 })
        ));
    }
}
