// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed};

use super::super::super::field::FieldValue;
use super::error::DocumentError;
use super::types::{
    DEFAULT_MAX_DOCUMENT_NESTING, DOCUMENT_BASE_CONTAINER_DEPTH, DocumentFormat,
    LAYER_LIMIT_SENTINEL, MAX_DOCUMENT_NESTING, PacketDocument,
};
use super::visitor::PacketDocumentSeed;

impl PacketDocument {
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
            super::super::super::build::DEFAULT_MAX_LAYERS,
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
            super::super::super::build::DEFAULT_MAX_LAYERS,
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
