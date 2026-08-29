// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed};

use super::error::Error;
use super::types::{DOCUMENT_BASE_CONTAINER_DEPTH, DocumentLimits, Format, Limit, Packet};
use super::visitor::{Budget, PacketSeed};

impl Packet {
    /// Parses one bounded JSON or YAML document with [`DocumentLimits::DEFAULT`]
    /// except for the input byte ceiling.
    pub fn parse(input: &str, format: Format, max_bytes: usize) -> Result<Self, Error> {
        Self::parse_with_limits(
            input,
            format,
            &DocumentLimits {
                max_input_bytes: max_bytes,
                ..DocumentLimits::DEFAULT
            },
        )
    }

    /// Parses one packet document while enforcing every [`DocumentLimits`]
    /// field during streaming deserialization.
    ///
    /// The input byte ceiling is checked first; every other limit is charged
    /// inside the deserializer before the bounded item is allocated, and both
    /// formats report the same [`Error`] for the same document.
    pub fn parse_with_limits(
        input: &str,
        format: Format,
        limits: &DocumentLimits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if input.len() > limits.max_input_bytes {
            return Err(Error::SizeLimit {
                actual: input.len(),
                limit: limits.max_input_bytes,
            });
        }
        let budget = Budget::new(limits);
        let seed = PacketSeed { budget: &budget };
        match format {
            Format::Json => {
                validate_json_container_depth(input, limits.max_nesting)?;
                let mut deserializer = serde_json::Deserializer::from_str(input);
                deserializer.disable_recursion_limit();
                let document = seed
                    .deserialize(&mut deserializer)
                    .map_err(|source| map_parse_error("JSON", source, &budget, limits))?;
                deserializer
                    .end()
                    .map_err(|source| map_parse_error("JSON", source, &budget, limits))?;
                Ok(document)
            }
            Format::Yaml => {
                // The YAML parser's own budgets are an outer envelope derived
                // from the input ceiling; every semantic limit trips first, so
                // the classified error is the same one JSON reports.
                let envelope = limits.max_input_bytes.max(1);
                let config = noyalib::ParserConfig::new()
                    .max_depth(document_container_depth(limits.max_nesting))
                    .max_document_length(limits.max_input_bytes)
                    .max_alias_expansions(0)
                    .max_mapping_keys(envelope)
                    .max_sequence_length(envelope)
                    .max_events(envelope.saturating_mul(2))
                    .max_nodes(envelope)
                    .max_total_scalar_bytes(limits.max_input_bytes)
                    .max_documents(1)
                    .max_merge_keys(0)
                    .duplicate_key_policy(noyalib::DuplicateKeyPolicy::Error)
                    .strict_booleans(true);
                let mut deserializer = noyalib::StreamingDeserializer::with_config(input, &config);
                let document = seed
                    .deserialize(&mut deserializer)
                    .map_err(|source| map_yaml_parse_error(source, &budget, limits))?;
                match de::IgnoredAny::deserialize(&mut deserializer) {
                    Ok(_) => Err(Error::Parse {
                        format: "YAML",
                        message: "multiple YAML documents are not supported".to_owned(),
                    }),
                    Err(source) if source.to_string().contains("parser has already finished") => {
                        Ok(document)
                    }
                    Err(source) => Err(map_yaml_parse_error(source, &budget, limits)),
                }
            }
        }
    }
}

fn document_container_depth(max_nesting: usize) -> usize {
    DOCUMENT_BASE_CONTAINER_DEPTH.saturating_add(max_nesting.saturating_mul(2))
}

/// Bounds raw JSON container depth before deserialization: the recursion
/// limit is disabled so the field-value seeds can own nesting, and the probe
/// that detects an over-long layer list may skip arbitrary content.
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

fn map_parse_error(
    format: &'static str,
    source: impl fmt::Display,
    budget: &Budget<'_>,
    limits: &DocumentLimits,
) -> Error {
    match budget.breach() {
        Some(limit) => Error::exceeded(limit, limits),
        None => Error::Parse {
            format,
            message: source.to_string(),
        },
    }
}

fn map_yaml_parse_error(
    source: noyalib::Error,
    budget: &Budget<'_>,
    limits: &DocumentLimits,
) -> Error {
    if budget.breach().is_none() && matches!(source, noyalib::Error::RecursionLimitExceeded { .. })
    {
        return Error::exceeded(Limit::Nesting, limits);
    }
    map_parse_error("YAML", source, budget, limits)
}
