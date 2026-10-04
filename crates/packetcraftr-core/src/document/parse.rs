// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod budget;
mod buffered;
mod seed;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed};

use super::error::Error;
use super::types::{DOCUMENT_BASE_CONTAINER_DEPTH, DocumentLimits, Format, Limit, Packet};
use budget::Budget;
use seed::PacketSeed;

impl Packet {
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
                let config = yaml_config(limits);
                let mut deserializer = noyalib::StreamingDeserializer::with_config(input, &config);
                let document = seed
                    .deserialize(&mut deserializer)
                    .map_err(|source| map_yaml_parse_error(source, &budget, limits))?;
                match de::IgnoredAny::deserialize(&mut deserializer) {
                    Ok(_) => Err(Error::Parse {
                        format: "YAML",
                        source: crate::error::Source::new(super::error::Refused(
                            "multiple YAML documents are not supported".to_owned(),
                        )),
                    }),
                    Err(source) if yaml_stream_ended(&source) => Ok(document),
                    Err(source) => Err(map_yaml_parse_error(source, &budget, limits)),
                }
            }
        }
    }
}

/// An outer envelope: every semantic limit trips first, so errors classify as JSON's do.
fn yaml_config(limits: &DocumentLimits) -> noyalib::ParserConfig {
    let envelope = limits.max_input_bytes.max(1);
    noyalib::ParserConfig::new()
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
        .strict_booleans(true)
}

/// The deserializer reports exhaustion as a scanner error; match only its exact message.
fn yaml_stream_ended(error: &noyalib::Error) -> bool {
    match error {
        noyalib::Error::Parse(message) | noyalib::Error::ParseWithLocation { message, .. } => {
            message == "parser has already finished"
        }
        _ => false,
    }
}

fn document_container_depth(max_nesting: usize) -> usize {
    DOCUMENT_BASE_CONTAINER_DEPTH.saturating_add(max_nesting.saturating_mul(2))
}

/// Bounds raw JSON depth up front, since the recursion limit is disabled so seeds own nesting.
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
    source: impl std::error::Error + Send + Sync + 'static,
    budget: &Budget<'_>,
    limits: &DocumentLimits,
) -> Error {
    match budget.breach() {
        Some(limit) => Error::exceeded(limit, limits),
        None => Error::Parse {
            format,
            source: crate::error::Source::new(source),
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

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_DOCUMENT: &str = concat!(
        "schema: packetcraftr.packet/v2\n",
        "layers:\n",
        "  - protocol: raw\n",
        "    fields:\n",
        "      bytes:\n",
        "        type: bytes\n",
        "        value: [1, 2]\n",
    );

    #[test]
    fn yaml_stream_exhaustion_is_distinct_from_parse_failure() {
        let limits = DocumentLimits::DEFAULT;
        let config = yaml_config(&limits);
        let mut deserializer = noyalib::StreamingDeserializer::with_config(ONE_DOCUMENT, &config);
        de::IgnoredAny::deserialize(&mut deserializer).expect("the one document reads");

        let error = de::IgnoredAny::deserialize(&mut deserializer)
            .expect_err("reading past the last document fails instead of ending cleanly");
        assert!(
            yaml_stream_ended(&error),
            "unexpected YAML end-of-stream error: {error}"
        );
        assert!(!yaml_stream_ended(&noyalib::Error::Parse(
            "invalid token: parser has already finished".to_owned()
        )));
    }

    #[test]
    fn eof_probe_distinguishes_exhausted_from_second_document() {
        let single =
            Packet::parse_with_limits(ONE_DOCUMENT, Format::Yaml, &DocumentLimits::DEFAULT)
                .expect("a single document parses through the end-of-stream probe");
        assert_eq!(single.layers.len(), 1);

        let two = format!("{ONE_DOCUMENT}---\n{ONE_DOCUMENT}");
        let error = Packet::parse_with_limits(&two, Format::Yaml, &DocumentLimits::DEFAULT)
            .expect_err("a second document is refused");
        let rendered = crate::error::render(&error);
        assert!(rendered.contains("multiple YAML documents"), "{rendered}");
    }
}
