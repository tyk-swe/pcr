// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::super::Packet;
use super::super::field::FieldValue;
use super::super::registry::{CodecError, ProtocolRegistry};

pub const PACKET_DOCUMENT_SCHEMA_V1: &str = "packetcraftr.packet/v1";
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
/// Absolute recursive `FieldValue::List` nesting accepted by the stable
/// packet-document parser.
pub const MAX_DOCUMENT_NESTING: usize = 64;
pub const DEFAULT_MAX_DOCUMENT_NESTING: usize = MAX_DOCUMENT_NESTING;
pub const DEFAULT_MAX_DOCUMENT_LAYERS: usize = 64;
pub const DEFAULT_MAX_FIELDS_PER_LAYER: usize = 256;
pub const DEFAULT_MAX_TOTAL_FIELDS: usize = 4_096;
pub const DEFAULT_MAX_AST_NODES: usize = 65_536;
pub const DEFAULT_MAX_COLLECTION_ITEMS: usize = 16_777_216;
pub const DEFAULT_MAX_KEY_BYTES: usize = 256;
pub const DEFAULT_MAX_OWNED_SCALAR_BYTES: usize = 16 * 1024 * 1024;

const DOCUMENT_BASE_CONTAINER_DEPTH: usize = 6;
const LAYER_LIMIT_SENTINEL: &str = "$__packetcraftr_document_layer_limit";
const BUDGET_LIMIT_SENTINEL: &str = "$__packetcraftr_document_budget_limit";

/// Allocation budgets enforced by the JSON/YAML preflight parser before the
/// semantic packet document is constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_layers: usize,
    pub max_nesting: usize,
    pub max_fields_per_layer: usize,
    pub max_total_fields: usize,
    pub max_ast_nodes: usize,
    pub max_collection_items: usize,
    pub max_key_bytes: usize,
    pub max_owned_scalar_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            max_layers: DEFAULT_MAX_DOCUMENT_LAYERS,
            max_nesting: DEFAULT_MAX_DOCUMENT_NESTING,
            max_fields_per_layer: DEFAULT_MAX_FIELDS_PER_LAYER,
            max_total_fields: DEFAULT_MAX_TOTAL_FIELDS,
            max_ast_nodes: DEFAULT_MAX_AST_NODES,
            max_collection_items: DEFAULT_MAX_COLLECTION_ITEMS,
            max_key_bytes: DEFAULT_MAX_KEY_BYTES,
            max_owned_scalar_bytes: DEFAULT_MAX_OWNED_SCALAR_BYTES,
        }
    }
}

impl Limits {
    fn for_max_bytes(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            max_ast_nodes: DEFAULT_MAX_AST_NODES.min(max_bytes),
            max_collection_items: DEFAULT_MAX_COLLECTION_ITEMS.min(max_bytes),
            max_key_bytes: DEFAULT_MAX_KEY_BYTES.min(max_bytes),
            max_owned_scalar_bytes: DEFAULT_MAX_OWNED_SCALAR_BYTES.min(max_bytes),
            ..Self::default()
        }
    }
}

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
    #[error("packet document resource {resource} reached {actual}, exceeding limit {limit}")]
    ResourceLimit {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
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
        Self::parse_with_options(input, format, Limits::for_max_bytes(max_bytes))
            .map_err(legacy_resource_error)
    }

    /// Parses one document with a caller-selected nesting ceiling and the
    /// stable default layer ceiling.
    pub fn parse_with_limits(
        input: &str,
        format: DocumentFormat,
        max_bytes: usize,
        max_nesting: usize,
    ) -> Result<Self, DocumentError> {
        let mut limits = Limits::for_max_bytes(max_bytes);
        limits.max_nesting = max_nesting;
        Self::parse_with_options(input, format, limits).map_err(legacy_resource_error)
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
        let mut limits = Limits::for_max_bytes(max_bytes);
        limits.max_layers = max_layers;
        limits.max_nesting = max_nesting;
        Self::parse_with_options(input, format, limits).map_err(legacy_resource_error)
    }

    /// Parses one packet document after an allocation-light preflight enforces
    /// all byte, layer, field, AST, collection, key, scalar, and nesting limits.
    pub fn parse_with_options(
        input: &str,
        format: DocumentFormat,
        limits: Limits,
    ) -> Result<Self, DocumentError> {
        if input.len() > limits.max_bytes {
            return Err(DocumentError::ResourceLimit {
                resource: "bytes",
                actual: input.len(),
                limit: limits.max_bytes,
            });
        }
        if limits.max_nesting > MAX_DOCUMENT_NESTING {
            return Err(DocumentError::InvalidLimit {
                field: "max_nesting",
                value: limits.max_nesting,
                maximum: MAX_DOCUMENT_NESTING,
            });
        }
        preflight_document(input, format, limits)?;
        let seed = PacketDocumentSeed {
            max_layers: limits.max_layers,
        };
        let document = match format {
            DocumentFormat::Json => {
                validate_json_container_depth(input, limits.max_nesting)
                    .map_err(resource_nesting_error)?;
                let mut deserializer = serde_json::Deserializer::from_str(input);
                deserializer.disable_recursion_limit();
                let document = seed.deserialize(&mut deserializer).map_err(|source| {
                    map_document_parse_error("JSON", source, limits.max_layers)
                })?;
                deserializer.end().map_err(|source| {
                    map_document_parse_error("JSON", source, limits.max_layers)
                })?;
                document
            }
            DocumentFormat::Yaml => {
                let config = yaml_parser_config(limits);
                let mut deserializer = noyalib::StreamingDeserializer::with_config(input, &config);
                let document = seed.deserialize(&mut deserializer).map_err(|source| {
                    map_yaml_parse_error(source, limits.max_layers, limits.max_nesting)
                })?;
                match de::IgnoredAny::deserialize(&mut deserializer) {
                    Ok(_) => {
                        return Err(DocumentError::Parse {
                            format: "YAML",
                            message: "multiple YAML documents are not supported".to_owned(),
                        });
                    }
                    Err(source) if source.to_string().contains("parser has already finished") => {}
                    Err(source) => {
                        return Err(map_yaml_parse_error(
                            source,
                            limits.max_layers,
                            limits.max_nesting,
                        ));
                    }
                }
                document
            }
        };
        validate_value_nesting(&document, limits.max_nesting).map_err(resource_nesting_error)?;
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
        noyalib::to_string(self).map_err(|source| DocumentError::Serialize {
            format: "YAML",
            message: source.to_string(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ResourceFailure {
    resource: &'static str,
    actual: usize,
    limit: usize,
}

struct DocumentBudget {
    limits: Limits,
    layers: usize,
    total_fields: usize,
    ast_nodes: usize,
    collection_items: usize,
    owned_scalar_bytes: usize,
    first_failure: Option<ResourceFailure>,
}

impl DocumentBudget {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            layers: 0,
            total_fields: 0,
            ast_nodes: 0,
            collection_items: 0,
            owned_scalar_bytes: 0,
            first_failure: None,
        }
    }

    fn charge_layers(&mut self) -> Result<(), ResourceFailure> {
        charge_counter(
            &mut self.layers,
            1,
            self.limits.max_layers,
            "layers",
            &mut self.first_failure,
        )
    }

    fn charge_field(&mut self, layer_fields: &mut usize) -> Result<(), ResourceFailure> {
        charge_counter(
            layer_fields,
            1,
            self.limits.max_fields_per_layer,
            "fields_per_layer",
            &mut self.first_failure,
        )?;
        charge_counter(
            &mut self.total_fields,
            1,
            self.limits.max_total_fields,
            "total_fields",
            &mut self.first_failure,
        )
    }

    fn charge_ast_node(&mut self) -> Result<(), ResourceFailure> {
        charge_counter(
            &mut self.ast_nodes,
            1,
            self.limits.max_ast_nodes,
            "ast_nodes",
            &mut self.first_failure,
        )
    }

    fn charge_collection_item(&mut self) -> Result<(), ResourceFailure> {
        charge_counter(
            &mut self.collection_items,
            1,
            self.limits.max_collection_items,
            "collection_items",
            &mut self.first_failure,
        )
    }

    fn charge_key(&mut self, key: &str) -> Result<(), ResourceFailure> {
        if key.len() > self.limits.max_key_bytes {
            return self.fail("key_bytes", key.len(), self.limits.max_key_bytes);
        }
        self.charge_scalar_bytes(key.len())
    }

    fn charge_scalar_bytes(&mut self, bytes: usize) -> Result<(), ResourceFailure> {
        charge_counter(
            &mut self.owned_scalar_bytes,
            bytes,
            self.limits.max_owned_scalar_bytes,
            "owned_scalar_bytes",
            &mut self.first_failure,
        )
    }

    fn check_nesting(&mut self, depth: usize) -> Result<(), ResourceFailure> {
        if depth > self.limits.max_nesting {
            return self.fail("nesting", depth, self.limits.max_nesting);
        }
        Ok(())
    }

    fn fail<T>(
        &mut self,
        resource: &'static str,
        actual: usize,
        limit: usize,
    ) -> Result<T, ResourceFailure> {
        let failure = ResourceFailure {
            resource,
            actual,
            limit,
        };
        self.first_failure.get_or_insert(failure);
        Err(failure)
    }
}

fn charge_counter(
    current: &mut usize,
    addition: usize,
    limit: usize,
    resource: &'static str,
    first_failure: &mut Option<ResourceFailure>,
) -> Result<(), ResourceFailure> {
    let actual = current.checked_add(addition).unwrap_or(usize::MAX);
    if actual > limit {
        let failure = ResourceFailure {
            resource,
            actual,
            limit,
        };
        first_failure.get_or_insert(failure);
        return Err(failure);
    }
    *current = actual;
    Ok(())
}

fn budget_result<E>(result: Result<(), ResourceFailure>) -> Result<(), E>
where
    E: de::Error,
{
    result.map_err(|_| de::Error::custom(BUDGET_LIMIT_SENTINEL))
}

fn preflight_document(
    input: &str,
    format: DocumentFormat,
    limits: Limits,
) -> Result<(), DocumentError> {
    let budget = RefCell::new(DocumentBudget::new(limits));
    let parse_result = match format {
        DocumentFormat::Json => {
            validate_json_container_depth(input, limits.max_nesting)
                .map_err(resource_nesting_error)?;
            let mut deserializer = serde_json::Deserializer::from_str(input);
            deserializer.disable_recursion_limit();
            let result = DocumentPreflightSeed { budget: &budget }
                .deserialize(&mut deserializer)
                .and_then(|()| deserializer.end());
            result.map_err(|source| DocumentError::Parse {
                format: "JSON",
                message: source.to_string(),
            })
        }
        DocumentFormat::Yaml => {
            let config = yaml_parser_config(limits);
            let mut deserializer = noyalib::StreamingDeserializer::with_config(input, &config);
            let result = DocumentPreflightSeed { budget: &budget }
                .deserialize(&mut deserializer)
                .map_err(|source| {
                    map_yaml_parse_error(source, limits.max_layers, limits.max_nesting)
                })
                .and_then(|()| match de::IgnoredAny::deserialize(&mut deserializer) {
                    Ok(_) => Err(DocumentError::Parse {
                        format: "YAML",
                        message: "multiple YAML documents are not supported".to_owned(),
                    }),
                    Err(source) if source.to_string().contains("parser has already finished") => {
                        Ok(())
                    }
                    Err(source) => Err(map_yaml_parse_error(
                        source,
                        limits.max_layers,
                        limits.max_nesting,
                    )),
                });
            result.map_err(resource_nesting_error)
        }
    };
    if let Some(failure) = budget.borrow().first_failure {
        return Err(DocumentError::ResourceLimit {
            resource: failure.resource,
            actual: failure.actual,
            limit: failure.limit,
        });
    }
    parse_result
}

fn yaml_parser_config(limits: Limits) -> noyalib::ParserConfig {
    let nodes = limits
        .max_ast_nodes
        .saturating_add(limits.max_collection_items)
        .saturating_add(limits.max_layers)
        .saturating_add(limits.max_total_fields)
        .saturating_add(8);
    noyalib::ParserConfig::new()
        .max_depth(document_container_depth(limits.max_nesting))
        .max_document_length(limits.max_bytes)
        .max_alias_expansions(0)
        .max_mapping_keys(limits.max_fields_per_layer.saturating_add(1).max(2))
        .max_sequence_length(
            limits
                .max_collection_items
                .max(limits.max_layers)
                .saturating_add(1),
        )
        .max_events(nodes.saturating_mul(3))
        .max_nodes(nodes)
        .max_total_scalar_bytes(limits.max_bytes)
        .max_documents(1)
        .max_merge_keys(0)
        .duplicate_key_policy(noyalib::DuplicateKeyPolicy::Error)
        .strict_booleans(true)
}

#[derive(Clone, Copy)]
struct DocumentPreflightSeed<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
}

impl<'de> DeserializeSeed<'de> for DocumentPreflightSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DocumentPreflightVisitor {
            budget: self.budget,
        })
    }
}

struct DocumentPreflightVisitor<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
}

impl<'de> Visitor<'de> for DocumentPreflightVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded packet document map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            budget_result(self.budget.borrow_mut().charge_key(&key))?;
            match key.as_str() {
                "layers" => map.next_value_seed(LayersPreflightSeed {
                    budget: self.budget,
                })?,
                _ => {
                    map.next_value_seed(ValuePreflightSeed {
                        budget: self.budget,
                        depth: 0,
                    })?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct LayersPreflightSeed<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
}

impl<'de> DeserializeSeed<'de> for LayersPreflightSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(LayersPreflightVisitor {
            budget: self.budget,
        })
    }
}

struct LayersPreflightVisitor<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
}

impl<'de> Visitor<'de> for LayersPreflightVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded sequence of packet layers")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(LayerPreflightSeed {
                budget: self.budget,
            })?
            .is_some()
        {}
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct LayerPreflightSeed<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
}

impl<'de> DeserializeSeed<'de> for LayerPreflightSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        {
            let mut budget = self.budget.borrow_mut();
            budget_result(budget.charge_collection_item())?;
            budget_result(budget.charge_layers())?;
        }
        deserializer.deserialize_map(LayerPreflightVisitor {
            budget: self.budget,
        })
    }
}

struct LayerPreflightVisitor<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
}

impl<'de> Visitor<'de> for LayerPreflightVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded packet layer map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            budget_result(self.budget.borrow_mut().charge_key(&key))?;
            match key.as_str() {
                "fields" => map.next_value_seed(FieldsPreflightSeed {
                    budget: self.budget,
                })?,
                _ => {
                    map.next_value_seed(ValuePreflightSeed {
                        budget: self.budget,
                        depth: 0,
                    })?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct FieldsPreflightSeed<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
}

impl<'de> DeserializeSeed<'de> for FieldsPreflightSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(FieldsPreflightVisitor {
            budget: self.budget,
        })
    }
}

struct FieldsPreflightVisitor<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
}

impl<'de> Visitor<'de> for FieldsPreflightVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded map of packet fields")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = 0usize;
        while let Some(key) = map.next_key::<String>()? {
            {
                let mut budget = self.budget.borrow_mut();
                budget_result(budget.charge_key(&key))?;
                budget_result(budget.charge_field(&mut fields))?;
            }
            map.next_value_seed(ValuePreflightSeed {
                budget: self.budget,
                depth: 0,
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
struct ValueSummary {
    top_sequence_items: usize,
}

#[derive(Clone, Copy)]
struct ValuePreflightSeed<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
    depth: usize,
}

#[derive(Clone, Copy)]
struct CollectionValuePreflightSeed<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for CollectionValuePreflightSeed<'_> {
    type Value = ValueSummary;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        budget_result(self.budget.borrow_mut().charge_collection_item())?;
        ValuePreflightSeed {
            budget: self.budget,
            depth: self.depth,
        }
        .deserialize(deserializer)
    }
}

impl<'de> DeserializeSeed<'de> for ValuePreflightSeed<'_> {
    type Value = ValueSummary;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ValuePreflightVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct ValuePreflightVisitor<'budget> {
    budget: &'budget RefCell<DocumentBudget>,
    depth: usize,
}

impl<'de> Visitor<'de> for ValuePreflightVisitor<'_> {
    type Value = ValueSummary;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded packet field value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(ValueSummary::default())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(ValueSummary::default())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(ValueSummary::default())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(ValueSummary::default())
    }

    fn visit_char<E>(self, value: char) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        budget_result(
            self.budget
                .borrow_mut()
                .charge_scalar_bytes(value.len_utf8()),
        )?;
        Ok(ValueSummary::default())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        budget_result(self.budget.borrow_mut().charge_scalar_bytes(value.len()))?;
        Ok(ValueSummary::default())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        budget_result(self.budget.borrow_mut().charge_scalar_bytes(value.len()))?;
        Ok(ValueSummary::default())
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_bytes(&value)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(ValueSummary::default())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(ValueSummary::default())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ValuePreflightSeed {
            budget: self.budget,
            depth: self.depth,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = 0usize;
        while sequence
            .next_element_seed(CollectionValuePreflightSeed {
                budget: self.budget,
                depth: self.depth.saturating_add(1),
            })?
            .is_some()
        {
            items = items.saturating_add(1);
        }
        Ok(ValueSummary {
            top_sequence_items: items,
        })
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        budget_result(self.budget.borrow_mut().charge_ast_node())?;
        let mut kind = None;
        let mut value = ValueSummary::default();
        while let Some(key) = map.next_key::<String>()? {
            budget_result(self.budget.borrow_mut().charge_key(&key))?;
            if key == "type" {
                let parsed = map.next_value::<String>()?;
                budget_result(self.budget.borrow_mut().charge_scalar_bytes(parsed.len()))?;
                kind = Some(parsed);
            } else {
                let parsed = map.next_value_seed(ValuePreflightSeed {
                    budget: self.budget,
                    depth: self.depth,
                })?;
                if key == "value" {
                    value = parsed;
                }
            }
        }
        match kind.as_deref() {
            Some("bytes") => budget_result(
                self.budget
                    .borrow_mut()
                    .charge_scalar_bytes(value.top_sequence_items),
            )?,
            Some("list") => budget_result(
                self.budget
                    .borrow_mut()
                    .check_nesting(self.depth.saturating_add(1)),
            )?,
            _ => {}
        }
        Ok(ValueSummary::default())
    }
}

fn legacy_resource_error(error: DocumentError) -> DocumentError {
    match error {
        DocumentError::ResourceLimit {
            resource: "bytes",
            actual,
            limit,
        } => DocumentError::SizeLimit { actual, limit },
        DocumentError::ResourceLimit {
            resource: "layers",
            limit,
            ..
        } => DocumentError::LayerLimit { limit },
        DocumentError::ResourceLimit {
            resource: "nesting",
            limit,
            ..
        } => DocumentError::NestingLimit { limit },
        error => error,
    }
}

fn resource_nesting_error(error: DocumentError) -> DocumentError {
    match error {
        DocumentError::NestingLimit { limit } => DocumentError::ResourceLimit {
            resource: "nesting",
            actual: limit.saturating_add(1),
            limit,
        },
        error => error,
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

    fn budget_documents() -> [(&'static str, DocumentFormat); 2] {
        [
            (
                r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw","fields":{"x":{"type":"text","value":"z"}}}]}"#,
                DocumentFormat::Json,
            ),
            (
                "schema: packetcraftr.packet/v1\nlayers:\n  - protocol: raw\n    fields:\n      x:\n        type: text\n        value: z\n",
                DocumentFormat::Yaml,
            ),
        ]
    }

    fn generous_limits(input: &str) -> Limits {
        Limits {
            max_bytes: input.len(),
            max_layers: 8,
            max_nesting: 8,
            max_fields_per_layer: 8,
            max_total_fields: 8,
            max_ast_nodes: 8,
            max_collection_items: 8,
            max_key_bytes: 32,
            max_owned_scalar_bytes: 1024,
        }
    }

    fn assert_resource_limit(
        error: DocumentError,
        expected_resource: &'static str,
        actual: usize,
        limit: usize,
    ) {
        assert!(matches!(
            error,
            DocumentError::ResourceLimit {
                resource,
                actual: found_actual,
                limit: found_limit,
            } if resource == expected_resource && found_actual == actual && found_limit == limit
        ));
    }

    #[test]
    fn json_and_yaml_preflight_enforce_each_flat_budget_at_the_boundary() {
        for (input, format) in budget_documents() {
            let limits = generous_limits(input);
            PacketDocument::parse_with_options(input, format, limits).unwrap();

            let mut bytes = limits;
            bytes.max_bytes = input.len() - 1;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, bytes).unwrap_err(),
                "bytes",
                input.len(),
                input.len() - 1,
            );

            let mut layers = limits;
            layers.max_layers = 0;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, layers).unwrap_err(),
                "layers",
                1,
                0,
            );

            let mut fields = limits;
            fields.max_fields_per_layer = 0;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, fields).unwrap_err(),
                "fields_per_layer",
                1,
                0,
            );

            let mut total_fields = limits;
            total_fields.max_total_fields = 0;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, total_fields).unwrap_err(),
                "total_fields",
                1,
                0,
            );

            let mut nodes = limits;
            nodes.max_ast_nodes = 0;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, nodes).unwrap_err(),
                "ast_nodes",
                1,
                0,
            );

            let mut collections = limits;
            collections.max_collection_items = 0;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, collections).unwrap_err(),
                "collection_items",
                1,
                0,
            );

            let mut key = limits;
            key.max_key_bytes = 8;
            PacketDocument::parse_with_options(input, format, key).unwrap();
            key.max_key_bytes = 7;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, key).unwrap_err(),
                "key_bytes",
                8,
                7,
            );

            let mut scalar = limits;
            scalar.max_owned_scalar_bytes = 66;
            PacketDocument::parse_with_options(input, format, scalar).unwrap();
            scalar.max_owned_scalar_bytes = 65;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, scalar).unwrap_err(),
                "owned_scalar_bytes",
                66,
                65,
            );
        }
    }

    #[test]
    fn json_and_yaml_preflight_enforce_nested_ast_and_collection_budgets() {
        let documents = [
            (
                r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw","fields":{"x":{"value":[{"value":[],"type":"list"}],"type":"list"}}}]}"#,
                DocumentFormat::Json,
            ),
            (
                "schema: packetcraftr.packet/v1\nlayers:\n  - protocol: raw\n    fields:\n      x:\n        value:\n          - value: []\n            type: list\n        type: list\n",
                DocumentFormat::Yaml,
            ),
        ];
        for (input, format) in documents {
            let mut limits = generous_limits(input);
            limits.max_ast_nodes = 2;
            limits.max_collection_items = 2;
            limits.max_nesting = 2;
            PacketDocument::parse_with_options(input, format, limits).unwrap();

            limits.max_ast_nodes = 1;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, limits).unwrap_err(),
                "ast_nodes",
                2,
                1,
            );
            limits.max_ast_nodes = 2;
            limits.max_collection_items = 1;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, limits).unwrap_err(),
                "collection_items",
                2,
                1,
            );
            limits.max_collection_items = 2;
            limits.max_nesting = 1;
            assert_resource_limit(
                PacketDocument::parse_with_options(input, format, limits).unwrap_err(),
                "nesting",
                2,
                1,
            );
        }
    }

    #[test]
    fn over_limit_field_is_rejected_before_its_value_is_traversed() {
        let json = r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw","fields":{"x":[this is deliberately malformed}}]}"#;
        let mut limits = generous_limits(json);
        limits.max_fields_per_layer = 0;
        assert_resource_limit(
            PacketDocument::parse_with_options(json, DocumentFormat::Json, limits).unwrap_err(),
            "fields_per_layer",
            1,
            0,
        );

        let large_value = (0..10_000).map(|_| "0").collect::<Vec<_>>().join(", ");
        let yaml = format!(
            "schema: packetcraftr.packet/v1\nlayers:\n  - protocol: raw\n    fields:\n      x: [{large_value}]\n"
        );
        let mut limits = generous_limits(&yaml);
        limits.max_fields_per_layer = 0;
        limits.max_collection_items = 20_000;
        assert_resource_limit(
            PacketDocument::parse_with_options(&yaml, DocumentFormat::Yaml, limits).unwrap_err(),
            "fields_per_layer",
            1,
            0,
        );
    }

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
