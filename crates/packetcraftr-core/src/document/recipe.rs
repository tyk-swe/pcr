// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;

use super::{DocumentLimits, Format, Packet};
use crate::document;
use crate::error::{Classification, Classified, Coordinate, source_chain};
use crate::expression;
use crate::registry::Registry;

impl Format {
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "yaml" | "yml" => Some(Self::Yaml),
            _ => None,
        }
    }

    pub fn sniff(input: &str) -> Option<Self> {
        let trimmed = input.trim_start();
        if trimmed.starts_with('{') {
            Some(Self::Json)
        } else if trimmed.starts_with("schema:") || trimmed.starts_with("---") {
            Some(Self::Yaml)
        } else {
            None
        }
    }
}

pub fn parse(
    input: &str,
    declared: Option<Format>,
    registry: &Registry,
    max_layers: usize,
) -> Result<crate::packet::Packet, Error> {
    let parse_document = |format| {
        Packet::parse_with_limits(
            input,
            format,
            &DocumentLimits {
                max_layers,
                ..DocumentLimits::DEFAULT
            },
        )
    };
    if let Some(format) = declared.or_else(|| Format::sniff(input)) {
        return parse_document(format)
            .and_then(|document| document.to_packet(registry, max_layers))
            .map_err(Error::Document);
    }
    let expression = match expression::parse(
        input,
        registry,
        expression::Options {
            max_layers,
            ..expression::Options::default()
        },
    ) {
        Ok(packet) => return Ok(packet),
        Err(error) => error,
    };
    match parse_document(Format::Yaml) {
        Ok(document) => document
            .to_packet(registry, max_layers)
            .map_err(Error::Document),
        Err(document) => Err(Error::Unrecognized {
            expression: Box::new(expression),
            document: Box::new(document),
        }),
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Document(document::Error),
    Unrecognized {
        expression: Box<expression::Error>,
        document: Box<document::Error>,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document(error) => error.fmt(formatter),
            Self::Unrecognized { expression, .. } => expression.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Document(error) => error.source(),
            Self::Unrecognized { expression, .. } => expression.source(),
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Document(error) => error.classification(),
            Self::Unrecognized { expression, .. } => expression.classification(),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Document(error) => error.context(),
            Self::Unrecognized { expression, .. } => expression.context(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Document(error) => error.causes(),
            Self::Unrecognized {
                expression,
                document,
            } => {
                let mut causes = expression.causes();
                causes.push(document.to_string());
                causes.extend(source_chain(document.as_ref()));
                causes
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_extensions_are_case_insensitive_and_explicit() {
        for (path, expected) in [
            ("packet.json", Some(Format::Json)),
            ("packet.JSON", Some(Format::Json)),
            ("packet.yaml", Some(Format::Yaml)),
            ("packet.yml", Some(Format::Yaml)),
            ("packet.txt", None),
            ("packet", None),
        ] {
            assert_eq!(Format::from_path(Path::new(path)), expected, "{path}");
        }
    }

    #[test]
    fn recipe_text_announces_its_format_after_leading_whitespace() {
        for (input, expected) in [
            (" \n{\"schema\": 1}", Some(Format::Json)),
            ("schema: packetcraftr.packet/v2", Some(Format::Yaml)),
            ("\t---\nlayers: []", Some(Format::Yaml)),
            ("ipv4()/udp()", None),
            ("layers: []", None),
        ] {
            assert_eq!(Format::sniff(input), expected, "{input:?}");
        }
    }
}
