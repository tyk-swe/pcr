// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use thiserror::Error;

use crate::packet::Packet;

use crate::error::{Classification, Classified, Kind};
use crate::field::FieldValue;
use crate::registry::Registry;

mod syntax;
#[cfg(test)]
mod tests;
mod value;

use syntax::{split_assignment, split_top_level_bounded, trim_at};

const DEFAULT_MAX_EXPRESSION_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_GENERATED_BYTES: usize = 1024 * 1024;
const MAX_EXPRESSION_NESTING: usize = 64;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("packet expression is empty")]
    Empty,
    #[error("packet expression has {actual} bytes, exceeding limit {limit}")]
    SizeLimit { actual: usize, limit: usize },
    #[error("packet expression has more than {limit} layers")]
    LayerLimit { limit: usize },
    #[error("packet expression generates {actual} bytes, exceeding limit {limit}")]
    GeneratedBytesLimit { actual: u64, limit: usize },
    #[error("packet expression nesting exceeds configured limit {limit}")]
    NestingLimit { limit: usize },
    #[error("packet expression nesting limit {value} exceeds stable maximum {maximum}")]
    InvalidNestingLimit { value: usize, maximum: usize },
    #[error("expression syntax error at byte {offset}: {message}")]
    Syntax { offset: usize, message: String },
    #[error("unknown protocol {name} at layer {layer}")]
    UnknownProtocol { layer: usize, name: String },
    #[error("duplicate field {field} at layer {layer}")]
    DuplicateField { layer: usize, field: String },
    #[error("could not construct layer {name} at index {layer}")]
    Layer {
        layer: usize,
        name: String,
        #[source]
        source: crate::codec::Error,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Empty | Self::Syntax { .. } | Self::DuplicateField { .. } => Classification::new(
                "cli.expression_syntax",
                Kind::Usage,
                Some("write one `protocol(field=value)` layer per `/`-separated segment"),
            ),
            Self::SizeLimit { .. }
            | Self::LayerLimit { .. }
            | Self::GeneratedBytesLimit { .. }
            | Self::NestingLimit { .. }
            | Self::InvalidNestingLimit { .. } => Classification::new(
                "cli.expression_limit",
                Kind::Usage,
                Some(
                    "shorten the expression to stay inside its byte, layer, nesting, and generated-byte bounds",
                ),
            ),
            Self::UnknownProtocol { .. } => Classification::new(
                "cli.expression_protocol",
                Kind::Usage,
                Some("run `packetcraftr protocols` to list the protocol names the registry binds"),
            ),
            Self::Layer { .. } => Classification::new(
                "cli.expression_field",
                Kind::Usage,
                Some("correct the layer's field names and values against its reflective schema"),
            ),
        }
    }
}

/// Ceilings on one packet expression.
///
/// Every value is honored as given: bytes, layers, and nesting beyond their
/// ceilings are refused where they occur, and zero refuses the corresponding
/// construct. `max_nesting` also has a stable maximum, which
/// [`validate`](Self::validate) enforces. `max_generated_bytes` caps the
/// total `repeat`, `zeros`, and `cyclic` output of one expression and is
/// checked before any of it is allocated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_layers: usize,
    pub max_nesting: usize,
    pub max_generated_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_EXPRESSION_BYTES,
            max_layers: crate::packet::DEFAULT_MAX_LAYERS,
            max_nesting: MAX_EXPRESSION_NESTING,
            max_generated_bytes: DEFAULT_MAX_GENERATED_BYTES,
        }
    }
}

impl Limits {
    /// Checks the ceilings against their stable maxima.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidNestingLimit`] when `max_nesting` exceeds the stable
    /// maximum.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_nesting > MAX_EXPRESSION_NESTING {
            return Err(Error::InvalidNestingLimit {
                value: self.max_nesting,
                maximum: MAX_EXPRESSION_NESTING,
            });
        }
        Ok(())
    }
}

pub fn parse(input: &str, registry: &Registry, limits: Limits) -> Result<Packet, Error> {
    if input.trim().is_empty() {
        return Err(Error::Empty);
    }
    if input.len() > limits.max_bytes {
        return Err(Error::SizeLimit {
            actual: input.len(),
            limit: limits.max_bytes,
        });
    }
    limits.validate()?;
    // Bound layers while scanning so delimiters cannot amplify a small byte budget.
    let segments = split_top_level_bounded(0, input, '/', Some(limits.max_layers))?;
    let mut packet = Packet::with_capacity(segments.len());
    let mut values = value::Parser::new(&limits);
    for (layer_index, (base, segment)) in segments.into_iter().enumerate() {
        let (name, fields) = parse_layer(base, segment, layer_index, &mut values)?;
        let codec = registry
            .codec_named(&name)
            .ok_or_else(|| Error::UnknownProtocol {
                layer: layer_index,
                name: name.clone(),
            })?;
        let layer = codec.make_layer(&fields).map_err(|source| Error::Layer {
            layer: layer_index,
            name: name.clone(),
            source,
        })?;
        layer
            .validate_required_fields()
            .map_err(|source| Error::Layer {
                layer: layer_index,
                name,
                source: crate::codec::Error::Field(source),
            })?;
        packet.push_boxed(layer);
    }
    Ok(packet)
}

/// `max_layers` has no effect because this input contains no layer stack.
pub fn parse_value(input: &str, limits: Limits) -> Result<FieldValue, Error> {
    if input.len() > limits.max_bytes {
        return Err(Error::SizeLimit {
            actual: input.len(),
            limit: limits.max_bytes,
        });
    }
    limits.validate()?;
    value::Parser::new(&limits).parse(0, input)
}

fn parse_layer(
    base: usize,
    segment: &str,
    layer: usize,
    values: &mut value::Parser,
) -> Result<(String, BTreeMap<String, FieldValue>), Error> {
    let (base, segment) = trim_at(base, segment);
    if segment.is_empty() {
        return Err(Error::Syntax {
            offset: base,
            message: "empty layer".to_owned(),
        });
    }
    let Some(open) = segment.find('(') else {
        return Ok((segment.to_ascii_lowercase(), BTreeMap::new()));
    };
    if !segment.ends_with(')') {
        return Err(Error::Syntax {
            offset: base.saturating_add(open),
            message: "layer arguments must end with ')'".to_owned(),
        });
    }
    let name = segment[..open].trim().to_ascii_lowercase();
    if name.is_empty() {
        return Err(Error::Syntax {
            offset: base,
            message: "missing protocol name".to_owned(),
        });
    }
    let arguments = &segment[open.saturating_add(1)..segment.len().saturating_sub(1)];
    let mut fields = BTreeMap::new();
    if arguments.trim().is_empty() {
        return Ok((name, fields));
    }
    let arguments_base = base.saturating_add(open).saturating_add(1);
    for (argument_base, argument) in split_top_level_bounded(arguments_base, arguments, ',', None)?
    {
        let Some((field, (value_base, raw_value))) = split_assignment(argument_base, argument)
        else {
            return Err(Error::Syntax {
                offset: trim_at(argument_base, argument).0,
                message: format!("expected field=value, got {argument}"),
            });
        };
        let (field_base, field) = trim_at(argument_base, field);
        let field = field.to_ascii_lowercase();
        if field.is_empty() {
            return Err(Error::Syntax {
                offset: field_base,
                message: "empty field name".to_owned(),
            });
        }
        let value = values.parse(value_base, raw_value)?;
        if fields.insert(field.clone(), value).is_some() {
            return Err(Error::DuplicateField { layer, field });
        }
    }
    Ok((name, fields))
}
