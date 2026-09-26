// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet recipes: text that is either a packet document or a layer
//! expression, and recipe fields filled with bytes from outside the recipe.

use std::path::Path;

use bytes::Bytes;

use super::{DocumentLimits, Error, Format, Packet};
use crate::error::{Classification, Classified, Coordinate, Kind, Source, source_chain};
use crate::expression;
use crate::field::{self, FieldValue};
use crate::registry::Registry;

impl Format {
    /// The format a file name declares by its extension (`json`, `yaml`, or
    /// `yml`, in any case), or `None` when it declares none.
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "yaml" | "yml" => Some(Self::Yaml),
            _ => None,
        }
    }

    /// The format recipe text announces by how it starts: a JSON object, or
    /// a YAML `schema:` key or `---` document marker after leading whitespace.
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

/// Reads recipe text as a packet with at most `max_layers` layers.
///
/// A `declared` format, or else the one [`Format::sniff`] finds, parses the
/// text as a packet document of that format. Text that announces no format is
/// a layer expression; if it is not one either, it is tried as a YAML
/// document, and when that also fails the expression failure is reported
/// with the document failure as its cause.
pub fn parse_recipe(
    input: &str,
    declared: Option<Format>,
    registry: &Registry,
    max_layers: usize,
) -> Result<crate::packet::Packet, RecipeError> {
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
            .map_err(RecipeError::Document);
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
            .map_err(RecipeError::Document),
        Err(document) => Err(RecipeError::Unrecognized {
            expression: Box::new(expression),
            document: Box::new(document),
        }),
    }
}

/// Why recipe text is not a packet.
#[derive(Debug)]
#[non_exhaustive]
pub enum RecipeError {
    /// The text is a packet document that does not describe a packet.
    Document(Error),
    /// The text is neither a layer expression nor a YAML packet document. It
    /// reads as the expression failure; the document failure is a cause.
    Unrecognized {
        expression: Box<expression::Error>,
        document: Box<Error>,
    },
}

impl std::fmt::Display for RecipeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document(error) => error.fmt(formatter),
            Self::Unrecognized { expression, .. } => expression.fmt(formatter),
        }
    }
}

impl std::error::Error for RecipeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Document(error) => error.source(),
            Self::Unrecognized { expression, .. } => expression.source(),
        }
    }
}

impl Classified for RecipeError {
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

/// A `LAYER.FIELD` recipe field that receives bytes from outside the
/// recipe: `LAYER` is a zero-based layer index and `FIELD` a field path,
/// read case-insensitively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadTarget {
    layer: usize,
    field: String,
}

impl std::str::FromStr for PayloadTarget {
    type Err = PayloadError;

    fn from_str(selector: &str) -> Result<Self, PayloadError> {
        let (layer, field) = selector
            .trim()
            .split_once('.')
            .ok_or(PayloadError::Syntax)?;
        let layer = layer.parse().map_err(|_| PayloadError::Syntax)?;
        let field = field.trim().to_ascii_lowercase();
        if field.is_empty() {
            return Err(PayloadError::Syntax);
        }
        Ok(Self { layer, field })
    }
}

impl PayloadTarget {
    /// The zero-based layer index.
    pub fn layer(&self) -> usize {
        self.layer
    }

    /// The field path, lowercased.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Fills the target field of `packet` with the bytes `load` returns.
    ///
    /// The field must exist, be bytes-typed, and be empty in the recipe;
    /// `load` runs only after those checks pass, so a bad target never reads
    /// its source.
    pub fn inject<E: From<PayloadError>>(
        &self,
        packet: &mut crate::packet::Packet,
        load: impl FnOnce() -> Result<Bytes, E>,
    ) -> Result<(), E> {
        let layers = packet.len();
        let layer = packet
            .layer_mut(self.layer)
            .ok_or(PayloadError::LayerOutOfRange {
                layer: self.layer,
                layers,
            })?;
        let unknown = || PayloadError::UnknownField {
            layer: self.layer,
            field: self.field.clone(),
        };
        let path = self.field.parse::<field::Path>().map_err(|_| unknown())?;
        let FieldValue::Bytes(current) = layer.field_path(&path).ok_or_else(unknown)? else {
            return Err(PayloadError::NotBytes {
                layer: self.layer,
                field: self.field.clone(),
            }
            .into());
        };
        if !current.is_empty() {
            return Err(PayloadError::Occupied {
                layer: self.layer,
                field: self.field.clone(),
            }
            .into());
        }
        let bytes = load()?;
        layer
            .set_field_path(&path, FieldValue::Bytes(bytes))
            .map_err(|source| {
                PayloadError::Set {
                    layer: self.layer,
                    field: self.field.clone(),
                    source: Source::new(source),
                }
                .into()
            })
    }
}

/// Why a payload target cannot receive bytes. The messages name the
/// `--payload-file` option they are published under.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PayloadError {
    /// The target is not `LAYER.FIELD=PATH` with a zero-based layer index.
    #[error("--payload-file requires LAYER.FIELD=PATH with a zero-based layer index")]
    Syntax,
    #[error("--payload-file layer index {layer} is outside the recipe's {layers} layers")]
    LayerOutOfRange { layer: usize, layers: usize },
    #[error("--payload-file field {field} is unknown on layer {layer}")]
    UnknownField { layer: usize, field: String },
    #[error("--payload-file field {field} on layer {layer} is not bytes-typed")]
    NotBytes { layer: usize, field: String },
    #[error("--payload-file field {field} on layer {layer} already holds recipe bytes")]
    Occupied { layer: usize, field: String },
    /// The layer refused the bytes. The message already names its reason.
    #[error("could not set --payload-file field {field} on layer {layer}: {source}")]
    Set {
        layer: usize,
        field: String,
        #[source]
        source: Source,
    },
}

impl Classified for PayloadError {
    fn classification(&self) -> Classification {
        Classification::new("cli.error", Kind::Usage, None)
    }

    fn causes(&self) -> Vec<String> {
        match self {
            // The message already carries the layer's reason.
            Self::Set { .. } => Vec::new(),
            _ => source_chain(self),
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

    #[test]
    fn payload_targets_parse_a_zero_based_layer_and_a_lowercased_field() {
        let target: PayloadTarget = " 2.BYTES ".parse().expect("valid target");
        assert_eq!((target.layer(), target.field()), (2, "bytes"));
        for invalid in ["2", "x.bytes", "-1.bytes", "2 .bytes", "2. "] {
            assert!(
                matches!(invalid.parse::<PayloadTarget>(), Err(PayloadError::Syntax)),
                "{invalid:?}"
            );
        }
    }
}
