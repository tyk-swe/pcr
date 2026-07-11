// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::packet::Packet;
use super::registry::{CodecError, ProtocolRegistry};
use super::value::FieldValue;

pub const PACKET_DOCUMENT_SCHEMA_V1: &str = "packetcraftr.packet/v1";
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_DOCUMENT_NESTING: usize = 64;
/// Absolute recursive `FieldValue::List` nesting accepted by the stable
/// packet-document parser.
pub const MAX_DOCUMENT_NESTING: usize = 64;

const DOCUMENT_BASE_CONTAINER_DEPTH: usize = 6;
const LAYER_LIMIT_SENTINEL: &str = "$__packetcraftr_document_layer_limit";

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
    #[error("packet document limit {field}={value} exceeds stable maximum {maximum}")]
    InvalidLimit {
        field: &'static str,
        value: usize,
        maximum: usize,
    },
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

    /// Parses one bounded JSON or YAML document with the stable default layer
    /// and nesting ceilings.
    pub fn parse(
        input: &str,
        format: DocumentFormat,
        max_bytes: usize,
    ) -> Result<Self, DocumentError> {
        Self::parse_with_resource_limits(
            input,
            format,
            max_bytes,
            super::build::DEFAULT_MAX_LAYERS,
            DEFAULT_MAX_DOCUMENT_NESTING,
        )
    }

    /// Parses one document with a caller-selected nesting ceiling and the
    /// stable default layer ceiling.
    pub fn parse_with_limits(
        input: &str,
        format: DocumentFormat,
        max_bytes: usize,
        max_nesting: usize,
    ) -> Result<Self, DocumentError> {
        Self::parse_with_resource_limits(
            input,
            format,
            max_bytes,
            super::build::DEFAULT_MAX_LAYERS,
            max_nesting,
        )
    }

    /// Parses one packet document while enforcing byte, layer, and nesting
    /// limits during lexical/streaming deserialization.
    pub fn parse_with_resource_limits(
        input: &str,
        format: DocumentFormat,
        max_bytes: usize,
        max_layers: usize,
        max_nesting: usize,
    ) -> Result<Self, DocumentError> {
        if input.len() > max_bytes {
            return Err(DocumentError::SizeLimit {
                actual: input.len(),
                limit: max_bytes,
            });
        }
        if max_nesting > MAX_DOCUMENT_NESTING {
            return Err(DocumentError::InvalidLimit {
                field: "max_nesting",
                value: max_nesting,
                maximum: MAX_DOCUMENT_NESTING,
            });
        }
        let seed = PacketDocumentSeed { max_layers };
        let document = match format {
            DocumentFormat::Json => {
                validate_json_container_depth(input, max_nesting)?;
                let mut deserializer = serde_json::Deserializer::from_str(input);
                deserializer.disable_recursion_limit();
                let document = seed
                    .deserialize(&mut deserializer)
                    .map_err(|source| map_document_parse_error("JSON", source, max_layers))?;
                deserializer
                    .end()
                    .map_err(|source| map_document_parse_error("JSON", source, max_layers))?;
                document
            }
            DocumentFormat::Yaml => {
                let collection_limit = max_bytes.max(1);
                let config = noyalib::ParserConfig::new()
                    .max_depth(document_container_depth(max_nesting))
                    .max_document_length(max_bytes)
                    .max_alias_expansions(0)
                    .max_mapping_keys(collection_limit)
                    .max_sequence_length(collection_limit)
                    .max_events(collection_limit.saturating_mul(2))
                    .max_nodes(collection_limit)
                    .max_total_scalar_bytes(max_bytes)
                    .max_documents(1)
                    .max_merge_keys(0)
                    .duplicate_key_policy(noyalib::DuplicateKeyPolicy::Error)
                    .strict_booleans(true);
                let mut deserializer = noyalib::StreamingDeserializer::with_config(input, &config);
                let document = seed
                    .deserialize(&mut deserializer)
                    .map_err(|source| map_yaml_parse_error(source, max_layers, max_nesting))?;
                match de::IgnoredAny::deserialize(&mut deserializer) {
                    Ok(_) => {
                        return Err(DocumentError::Parse {
                            format: "YAML",
                            message: "multiple YAML documents are not supported".to_owned(),
                        });
                    }
                    Err(source) if source.to_string().contains("parser has already finished") => {}
                    Err(source) => {
                        return Err(map_yaml_parse_error(source, max_layers, max_nesting));
                    }
                }
                document
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

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum PacketDocumentField {
    Schema,
    Layers,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum LayerDocumentField {
    Protocol,
    Fields,
}

#[derive(Clone, Copy)]
struct PacketDocumentSeed {
    max_layers: usize,
}

impl<'de> DeserializeSeed<'de> for PacketDocumentSeed {
    type Value = PacketDocument;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "PacketDocument",
            &["schema", "layers"],
            PacketDocumentVisitor {
                max_layers: self.max_layers,
            },
        )
    }
}

struct PacketDocumentVisitor {
    max_layers: usize,
}

impl<'de> Visitor<'de> for PacketDocumentVisitor {
    type Value = PacketDocument;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a packet document object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut schema = None;
        let mut layers = None;
        while let Some(field) = map.next_key::<PacketDocumentField>()? {
            match field {
                PacketDocumentField::Schema => {
                    if schema.is_some() {
                        return Err(de::Error::duplicate_field("schema"));
                    }
                    schema = Some(map.next_value()?);
                }
                PacketDocumentField::Layers => {
                    if layers.is_some() {
                        return Err(de::Error::duplicate_field("layers"));
                    }
                    layers = Some(map.next_value_seed(LayersSeed {
                        maximum: self.max_layers,
                    })?);
                }
            }
        }
        Ok(PacketDocument {
            schema: schema.ok_or_else(|| de::Error::missing_field("schema"))?,
            layers: layers.ok_or_else(|| de::Error::missing_field("layers"))?,
        })
    }
}

#[derive(Clone, Copy)]
struct LayersSeed {
    maximum: usize,
}

impl<'de> DeserializeSeed<'de> for LayersSeed {
    type Value = Vec<LayerDocument>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(LayersVisitor {
            maximum: self.maximum,
        })
    }
}

struct LayersVisitor {
    maximum: usize,
}

impl<'de> Visitor<'de> for LayersVisitor {
    type Value = Vec<LayerDocument>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} packet layers", self.maximum)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|length| length > self.maximum)
        {
            return Err(de::Error::custom(LAYER_LIMIT_SENTINEL));
        }
        let mut layers = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
        while layers.len() < self.maximum {
            let Some(layer) = sequence.next_element_seed(LayerDocumentSeed)? else {
                return Ok(layers);
            };
            layers.push(layer);
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(LAYER_LIMIT_SENTINEL));
        }
        Ok(layers)
    }
}

#[derive(Clone, Copy)]
struct LayerDocumentSeed;

impl<'de> DeserializeSeed<'de> for LayerDocumentSeed {
    type Value = LayerDocument;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "LayerDocument",
            &["protocol", "fields"],
            LayerDocumentVisitor,
        )
    }
}

struct LayerDocumentVisitor;

impl<'de> Visitor<'de> for LayerDocumentVisitor {
    type Value = LayerDocument;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a packet layer object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut protocol = None;
        let mut fields = None;
        while let Some(field) = map.next_key::<LayerDocumentField>()? {
            match field {
                LayerDocumentField::Protocol => {
                    if protocol.is_some() {
                        return Err(de::Error::duplicate_field("protocol"));
                    }
                    protocol = Some(map.next_value()?);
                }
                LayerDocumentField::Fields => {
                    if fields.is_some() {
                        return Err(de::Error::duplicate_field("fields"));
                    }
                    fields = Some(map.next_value_seed(FieldsSeed)?);
                }
            }
        }
        Ok(LayerDocument {
            protocol: protocol.ok_or_else(|| de::Error::missing_field("protocol"))?,
            fields: fields.unwrap_or_default(),
        })
    }
}

#[derive(Clone, Copy)]
struct FieldsSeed;

impl<'de> DeserializeSeed<'de> for FieldsSeed {
    type Value = BTreeMap<String, FieldValue>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(FieldsVisitor)
    }
}

struct FieldsVisitor;

impl<'de> Visitor<'de> for FieldsVisitor {
    type Value = BTreeMap<String, FieldValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of unique reflective field names")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = BTreeMap::new();
        while let Some(name) = map.next_key::<String>()? {
            if fields.contains_key(&name) {
                return Err(de::Error::custom(format!(
                    "duplicate reflective field {name:?}"
                )));
            }
            fields.insert(name, map.next_value()?);
        }
        Ok(fields)
    }
}

fn document_container_depth(max_nesting: usize) -> usize {
    DOCUMENT_BASE_CONTAINER_DEPTH.saturating_add(max_nesting.saturating_mul(2))
}

fn validate_json_container_depth(input: &str, max_nesting: usize) -> Result<(), DocumentError> {
    let maximum = document_container_depth(max_nesting);
    let bytes = input.as_bytes();
    let mut depth = 0_usize;
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                index += 1;
                while index < bytes.len() {
                    match bytes[index] {
                        b'\\' => index = index.saturating_add(2),
                        b'"' => break,
                        _ => index += 1,
                    }
                }
            }
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > maximum {
                    return Err(DocumentError::NestingLimit { limit: max_nesting });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

fn map_document_parse_error(
    format: &'static str,
    source: impl fmt::Display,
    max_layers: usize,
) -> DocumentError {
    let message = source.to_string();
    if message.contains(LAYER_LIMIT_SENTINEL) {
        DocumentError::LayerLimit { limit: max_layers }
    } else {
        DocumentError::Parse { format, message }
    }
}

fn map_yaml_parse_error(
    source: noyalib::Error,
    max_layers: usize,
    max_nesting: usize,
) -> DocumentError {
    if matches!(source, noyalib::Error::RecursionLimitExceeded { .. }) {
        DocumentError::NestingLimit { limit: max_nesting }
    } else {
        map_document_parse_error("YAML", source, max_layers)
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
        assert_eq!(
            document.layers[0].fields.get("bytes"),
            Some(&FieldValue::Bytes(Bytes::from_static(b"hello")))
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

        let yaml = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        type: list
        value:
          - type: list
            value:
              - type: list
                value: []
"#;
        assert!(matches!(
            PacketDocument::parse_with_limits(yaml, DocumentFormat::Yaml, 4096, 2),
            Err(DocumentError::NestingLimit { limit: 2 })
        ));
    }

    #[test]
    fn layer_limits_fire_during_json_and_yaml_deserialization() {
        let json = r#"{
            "schema":"packetcraftr.packet/v1",
            "layers":[{"protocol":"raw"},{"protocol":"raw"}]
        }"#;
        let yaml = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: raw
  - protocol: raw
"#;
        for (format, input) in [(DocumentFormat::Json, json), (DocumentFormat::Yaml, yaml)] {
            assert!(matches!(
                PacketDocument::parse_with_resource_limits(input, format, 4096, 1, 8),
                Err(DocumentError::LayerLimit { limit: 1 })
            ));
        }
    }

    #[test]
    fn stable_document_parser_rejects_ambiguous_or_amplifying_yaml() {
        let multiple = r#"
schema: packetcraftr.packet/v1
layers: []
---
schema: packetcraftr.packet/v1
layers: []
"#;
        assert!(matches!(
            PacketDocument::parse(multiple, DocumentFormat::Yaml, 4096),
            Err(DocumentError::Parse { .. })
        ));

        let alias = r#"
schema: packetcraftr.packet/v1
layers:
  - &raw
    protocol: raw
  - *raw
"#;
        assert!(matches!(
            PacketDocument::parse(alias, DocumentFormat::Yaml, 4096),
            Err(DocumentError::Parse { .. })
        ));

        let custom_tag = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: !application raw
"#;
        assert!(matches!(
            PacketDocument::parse(custom_tag, DocumentFormat::Yaml, 4096),
            Err(DocumentError::Parse { .. })
        ));

        let duplicate = r#"
schema: packetcraftr.packet/v1
schema: packetcraftr.packet/v1
layers: []
"#;
        assert!(matches!(
            PacketDocument::parse(duplicate, DocumentFormat::Yaml, 4096),
            Err(DocumentError::Parse { .. })
        ));
    }

    #[test]
    fn duplicate_reflective_fields_and_excess_limit_requests_are_rejected() {
        let duplicate = r#"{
            "schema":"packetcraftr.packet/v1",
            "layers":[{"protocol":"raw","fields":{
                "bytes":{"type":"bytes","value":[0]},
                "bytes":{"type":"bytes","value":[1]}
            }}]
        }"#;
        assert!(matches!(
            PacketDocument::parse(duplicate, DocumentFormat::Json, 4096),
            Err(DocumentError::Parse { .. })
        ));
        for unknown in [
            r#"{"schema":"packetcraftr.packet/v1","layers":[],"timeout":1}"#,
            r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw","route":"lab0"}]}"#,
            r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw","fields":{"bytes":{"type":"bytes","value":[],"encoding":"hex"}}}]}"#,
        ] {
            let result = PacketDocument::parse(unknown, DocumentFormat::Json, 4096);
            assert!(
                matches!(&result, Err(DocumentError::Parse { .. })),
                "{unknown}: {result:?}"
            );
        }
        let unknown_yaml = r#"
schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        type: bytes
        value: []
        encoding: hex
"#;
        assert!(matches!(
            PacketDocument::parse(unknown_yaml, DocumentFormat::Yaml, 4096),
            Err(DocumentError::Parse { .. })
        ));
        assert!(matches!(
            PacketDocument::parse_with_resource_limits(
                r#"{"schema":"packetcraftr.packet/v1","layers":[]}"#,
                DocumentFormat::Json,
                4096,
                64,
                MAX_DOCUMENT_NESTING + 1,
            ),
            Err(DocumentError::InvalidLimit {
                field: "max_nesting",
                ..
            })
        ));
    }

    #[test]
    fn the_absolute_nesting_boundary_is_accepted_and_the_next_level_is_rejected() {
        let mut value = FieldValue::Bytes(Bytes::new());
        for _ in 0..MAX_DOCUMENT_NESTING {
            value = FieldValue::List(vec![value]);
        }
        let document = PacketDocument {
            schema: PACKET_DOCUMENT_SCHEMA_V1.to_owned(),
            layers: vec![LayerDocument {
                protocol: "raw".to_owned(),
                fields: BTreeMap::from([("bytes".to_owned(), value.clone())]),
            }],
        };
        let json = document.to_json_pretty().unwrap();
        let yaml = document.to_yaml().unwrap();
        for (format, input) in [
            (DocumentFormat::Json, json.as_str()),
            (DocumentFormat::Yaml, yaml.as_str()),
        ] {
            PacketDocument::parse_with_limits(input, format, 64 * 1024, MAX_DOCUMENT_NESTING)
                .unwrap();
        }

        let too_deep = PacketDocument {
            schema: PACKET_DOCUMENT_SCHEMA_V1.to_owned(),
            layers: vec![LayerDocument {
                protocol: "raw".to_owned(),
                fields: BTreeMap::from([("bytes".to_owned(), FieldValue::List(vec![value]))]),
            }],
        };
        let json = too_deep.to_json_pretty().unwrap();
        let yaml = too_deep.to_yaml().unwrap();
        for (format, input) in [
            (DocumentFormat::Json, json.as_str()),
            (DocumentFormat::Yaml, yaml.as_str()),
        ] {
            assert!(matches!(
                PacketDocument::parse_with_limits(input, format, 64 * 1024, MAX_DOCUMENT_NESTING,),
                Err(DocumentError::NestingLimit {
                    limit: MAX_DOCUMENT_NESTING
                })
            ));
        }
    }
}
