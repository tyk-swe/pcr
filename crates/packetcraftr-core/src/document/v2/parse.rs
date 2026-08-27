// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use bytes::Bytes;
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use super::types::{Document, Layer, PACKET_DOCUMENT_SCHEMA_V2, Value};
use crate::document::error::Error;
use crate::document::types::{
    DEFAULT_MAX_DOCUMENT_NESTING, DOCUMENT_BASE_CONTAINER_DEPTH, Format, LAYER_LIMIT_SENTINEL,
    MAX_DOCUMENT_NESTING,
};

const MISSING_SCHEMA_SENTINEL: &str = "$__packetcraftr_missing_schema";
const UNKNOWN_SCHEMA_PREFIX: &str = "$__packetcraftr_unknown_schema:";
const LAYER_SHAPE_PREFIX: &str = "$__packetcraftr_layer_shape:";

impl Document {
    /// Detects the declared document schema string cheaply without parsing full payloads.
    pub fn detect_schema(input: &str) -> Option<&str> {
        let trimmed = input.trim_start();
        if let Some(idx) = trimmed.find("schema") {
            let after = trimmed.get(idx.saturating_add(6)..)?;
            let after_trimmed = after.trim_start();
            let after_colon = if let Some(stripped) = after_trimmed.strip_prefix(':') {
                stripped.trim_start()
            } else if let Some(stripped) = after_trimmed.strip_prefix("\":") {
                stripped.trim_start()
            } else {
                let stripped = after_trimmed.strip_prefix("\" :")?;
                stripped.trim_start()
            };
            let unquoted = after_colon.strip_prefix('"').unwrap_or(after_colon);
            let end_idx = unquoted
                .find(|c: char| c.is_whitespace() || c == '"' || c == ',' || c == '}' || c == '#')
                .unwrap_or(unquoted.len());
            let val = unquoted.get(..end_idx)?;
            if !val.is_empty() {
                return Some(val);
            }
        }
        None
    }

    /// Parses one bounded JSON or YAML v2 document with default resource limits.
    pub fn parse(input: &str, format: Format, max_bytes: usize) -> Result<Self, Error> {
        Self::parse_with_resource_limits(
            input,
            format,
            max_bytes,
            crate::build::DEFAULT_MAX_LAYERS,
            DEFAULT_MAX_DOCUMENT_NESTING,
        )
    }

    /// Parses one v2 packet document with explicit resource limits.
    pub fn parse_with_resource_limits(
        input: &str,
        format: Format,
        max_bytes: usize,
        max_layers: usize,
        max_nesting: usize,
    ) -> Result<Self, Error> {
        if input.len() > max_bytes {
            return Err(Error::SizeLimit {
                actual: input.len(),
                limit: max_bytes,
            });
        }
        if max_nesting > MAX_DOCUMENT_NESTING {
            return Err(Error::InvalidLimit {
                field: "max_nesting",
                value: max_nesting,
                maximum: MAX_DOCUMENT_NESTING,
            });
        }
        let seed = V2DocumentSeed { max_layers };
        let document = match format {
            Format::Json => {
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
            Format::Yaml => {
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
                    .strict_booleans(true)
                    .no_schema(true);
                let mut deserializer = noyalib::StreamingDeserializer::with_config(input, &config);
                let document = seed
                    .deserialize(&mut deserializer)
                    .map_err(|source| map_yaml_parse_error(source, max_layers, max_nesting))?;
                match de::IgnoredAny::deserialize(&mut deserializer) {
                    Ok(_) => {
                        return Err(Error::Parse {
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
        Ok(document)
    }
}

fn document_container_depth(max_nesting: usize) -> usize {
    DOCUMENT_BASE_CONTAINER_DEPTH.saturating_add(max_nesting.saturating_mul(2))
}

fn validate_json_container_depth(input: &str, max_nesting: usize) -> Result<(), Error> {
    let maximum = document_container_depth(max_nesting);
    let bytes = input.as_bytes();
    let mut depth = 0_usize;
    let mut index = 0_usize;
    while let Some(byte) = bytes.get(index).copied() {
        match byte {
            b'"' => {
                index = index.saturating_add(1);
                while let Some(quoted) = bytes.get(index).copied() {
                    match quoted {
                        b'\\' => index = index.saturating_add(2),
                        b'"' => break,
                        _ => index = index.saturating_add(1),
                    }
                }
            }
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > maximum {
                    return Err(Error::NestingLimit { limit: max_nesting });
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

fn map_document_parse_error(
    format: &'static str,
    source: impl fmt::Display,
    max_layers: usize,
) -> Error {
    let message = source.to_string();
    if message.contains(LAYER_LIMIT_SENTINEL) {
        return Error::LayerLimit { limit: max_layers };
    }
    if message.contains(MISSING_SCHEMA_SENTINEL) {
        return Error::UnknownSchema {
            got: "<missing>".to_owned(),
        };
    }
    if let Some(idx) = message.find(UNKNOWN_SCHEMA_PREFIX)
        && let Some(after) = message.get(idx.saturating_add(UNKNOWN_SCHEMA_PREFIX.len())..)
    {
        let schema = after.split([' ', '\n', '"', '\'']).next().unwrap_or(after);
        return Error::UnknownSchema {
            got: schema.to_owned(),
        };
    }
    if let Some(idx) = message.find(LAYER_SHAPE_PREFIX)
        && let Some(after) = message.get(idx.saturating_add(LAYER_SHAPE_PREFIX.len())..)
    {
        let mut parts = after.splitn(3, ':');
        let layer_idx = parts
            .next()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        let detail = parts.next().unwrap_or("invalid shape").to_owned();
        let keys_str = parts.next().unwrap_or("");
        let keys = if keys_str.is_empty() {
            Vec::new()
        } else {
            keys_str.split(',').map(|s| s.to_owned()).collect()
        };
        return Error::LayerShape {
            layer: layer_idx,
            keys,
            detail,
        };
    }
    Error::Parse { format, message }
}

fn map_yaml_parse_error(source: noyalib::Error, max_layers: usize, max_nesting: usize) -> Error {
    if matches!(source, noyalib::Error::RecursionLimitExceeded { .. }) {
        Error::NestingLimit { limit: max_nesting }
    } else {
        map_document_parse_error("YAML", source, max_layers)
    }
}

#[derive(Clone, Copy)]
struct V2DocumentSeed {
    max_layers: usize,
}

impl<'de> DeserializeSeed<'de> for V2DocumentSeed {
    type Value = Document;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(V2DocumentVisitor {
            max_layers: self.max_layers,
        })
    }
}

impl<'de> serde::Deserialize<'de> for Document {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        V2DocumentSeed {
            max_layers: crate::build::DEFAULT_MAX_LAYERS,
        }
        .deserialize(deserializer)
    }
}

struct V2DocumentVisitor {
    max_layers: usize,
}

impl<'de> Visitor<'de> for V2DocumentVisitor {
    type Value = Document;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a packet/v2 document")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut schema: Option<String> = None;
        let mut layers: Option<Vec<Layer>> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "schema" => {
                    if schema.is_some() {
                        return Err(de::Error::duplicate_field("schema"));
                    }
                    schema = Some(map.next_value()?);
                }
                "layers" => {
                    if layers.is_some() {
                        return Err(de::Error::duplicate_field("layers"));
                    }
                    layers = Some(map.next_value_seed(V2LayersSeed {
                        maximum: self.max_layers,
                    })?);
                }
                other => {
                    return Err(de::Error::unknown_field(other, &["schema", "layers"]));
                }
            }
        }

        let schema = schema.ok_or_else(|| de::Error::custom(MISSING_SCHEMA_SENTINEL))?;
        if schema != PACKET_DOCUMENT_SCHEMA_V2 {
            return Err(de::Error::custom(format!(
                "{UNKNOWN_SCHEMA_PREFIX}{schema}"
            )));
        }

        let layers = layers.ok_or_else(|| de::Error::missing_field("layers"))?;
        Ok(Document { layers })
    }
}

#[derive(Clone, Copy)]
struct V2LayersSeed {
    maximum: usize,
}

impl<'de> DeserializeSeed<'de> for V2LayersSeed {
    type Value = Vec<Layer>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(V2LayersVisitor {
            maximum: self.maximum,
        })
    }
}

struct V2LayersVisitor {
    maximum: usize,
}

impl<'de> Visitor<'de> for V2LayersVisitor {
    type Value = Vec<Layer>;

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
            let layer_index = layers.len();
            let Some(layer) = sequence.next_element_seed(V2LayerSeed { layer_index })? else {
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
struct V2LayerSeed {
    layer_index: usize,
}

impl<'de> DeserializeSeed<'de> for V2LayerSeed {
    type Value = Layer;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(V2LayerVisitor {
            layer_index: self.layer_index,
        })
    }
}

struct V2LayerVisitor {
    layer_index: usize,
}

impl<'de> Visitor<'de> for V2LayerVisitor {
    type Value = Layer;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a single-key map {<protocol>: {<fields>}}")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom(format!(
            "{LAYER_SHAPE_PREFIX}{}:scalar `{v}`:",
            self.layer_index
        )))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&v)
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom(format!(
            "{LAYER_SHAPE_PREFIX}{}:scalar `{v}`:",
            self.layer_index
        )))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom(format!(
            "{LAYER_SHAPE_PREFIX}{}:scalar `{v}`:",
            self.layer_index
        )))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom(format!(
            "{LAYER_SHAPE_PREFIX}{}:scalar `{v}`:",
            self.layer_index
        )))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(de::Error::custom(format!(
            "{LAYER_SHAPE_PREFIX}{}:scalar `{v}`:",
            self.layer_index
        )))
    }

    fn visit_seq<A>(self, _seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        Err(de::Error::custom(format!(
            "{LAYER_SHAPE_PREFIX}{}:sequence:",
            self.layer_index
        )))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut protocol = None;
        let mut fields = None;
        let mut keys = Vec::new();

        while let Some(key) = map.next_key::<String>()? {
            keys.push(key.clone());
            if protocol.is_none() {
                protocol = Some(key);
                fields = Some(map.next_value_seed(V2FieldsSeed {
                    layer_index: self.layer_index,
                })?);
            } else {
                let _ = map.next_value::<de::IgnoredAny>()?;
            }
        }

        if keys.len() != 1 {
            let detail = if keys.is_empty() {
                "empty map".to_owned()
            } else {
                format!("multiple keys {:?}", keys)
            };
            return Err(de::Error::custom(format!(
                "{LAYER_SHAPE_PREFIX}{}:{}:{}",
                self.layer_index,
                detail,
                keys.join(",")
            )));
        }

        Ok(Layer {
            protocol: protocol.unwrap_or_default(),
            fields: fields.unwrap_or_default(),
        })
    }
}

#[derive(Clone, Copy)]
struct V2FieldsSeed {
    #[allow(dead_code)]
    layer_index: usize,
}

impl<'de> DeserializeSeed<'de> for V2FieldsSeed {
    type Value = Vec<(String, Value)>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(V2FieldsVisitor)
    }
}

struct V2FieldsVisitor;

impl<'de> Visitor<'de> for V2FieldsVisitor {
    type Value = Vec<(String, Value)>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of field names to values")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if fields.iter().any(|(k, _)| k == &key) {
                return Err(de::Error::custom(format!(
                    "duplicate field in document: {key}"
                )));
            }
            let value = map.next_value_seed(V2ValueSeed)?;
            fields.push((key, value));
        }
        Ok(fields)
    }
}

#[derive(Clone, Copy)]
struct V2ValueSeed;

impl<'de> DeserializeSeed<'de> for V2ValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(V2ValueVisitor)
    }
}

struct V2ValueVisitor;

impl<'de> Visitor<'de> for V2ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a scalar, list of scalars, or {raw: 0x...} map")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Scalar(v.to_string()))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Scalar(v.to_string()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Scalar(v.to_string()))
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Scalar(v.to_string()))
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Scalar(v.to_string()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Scalar(v.to_string()))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.eq_ignore_ascii_case("auto") {
            Ok(Value::Auto)
        } else {
            Ok(Value::Scalar(v.to_owned()))
        }
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.eq_ignore_ascii_case("auto") {
            Ok(Value::Auto)
        } else {
            Ok(Value::Scalar(v))
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(ScalarStringSeed)? {
            items.push(item);
        }
        Ok(Value::List(items))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut raw_bytes = None;
        let mut keys = Vec::new();

        while let Some(key) = map.next_key::<String>()? {
            keys.push(key.clone());
            if key == "raw" {
                if raw_bytes.is_some() {
                    return Err(de::Error::duplicate_field("raw"));
                }
                let raw_str = map.next_value_seed(ScalarStringSeed)?;
                let hex = raw_str
                    .strip_prefix("0x")
                    .or_else(|| raw_str.strip_prefix("0X"))
                    .unwrap_or(&raw_str);
                if hex.is_empty() {
                    raw_bytes = Some(Bytes::new());
                } else if hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    let hex_b = hex.as_bytes();
                    let mut b = Vec::with_capacity(hex_b.len() / 2);
                    for chunk in hex_b.chunks_exact(2) {
                        if let (Some(&h), Some(&l)) = (chunk.first(), chunk.get(1))
                            && let (Some(nh), Some(nl)) = (hex_nibble(h), hex_nibble(l))
                        {
                            b.push((nh << 4) | nl);
                        }
                    }
                    raw_bytes = Some(Bytes::from(b));
                } else {
                    return Err(de::Error::custom(format!(
                        "invalid raw byte hex string `{raw_str}`"
                    )));
                }
            } else {
                let _ = map.next_value::<de::IgnoredAny>()?;
            }
        }

        if keys.len() != 1 || raw_bytes.is_none() {
            return Err(de::Error::custom(
                "expected single-key map {raw: 0x...} for raw value",
            ));
        }

        Ok(Value::Raw(raw_bytes.unwrap_or_default()))
    }
}

#[derive(Clone, Copy)]
struct ScalarStringSeed;

impl<'de> DeserializeSeed<'de> for ScalarStringSeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ScalarStringVisitor)
    }
}

struct ScalarStringVisitor;

impl<'de> Visitor<'de> for ScalarStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a scalar string, boolean, or number")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_string())
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_string())
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_string())
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_string())
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_string())
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_string())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_owned())
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v)
    }
}

#[expect(
    clippy::arithmetic_side_effects,
    reason = "ASCII character values are bounded by matching branches, so arithmetic stays within u8"
)]
fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
