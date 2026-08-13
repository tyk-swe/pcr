// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compact packet expressions.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use bytes::Bytes;
use thiserror::Error;

use crate::Packet;
use crate::field::{FieldValue, parse_mac};
use crate::registry::{CodecError, ProtocolRegistry};

pub use ExpressionError as Error;
pub use ExpressionOptions as Options;
pub use parse_packet_expression as parse;

pub const DEFAULT_MAX_EXPRESSION_BYTES: usize = 1024 * 1024;
/// Absolute recursive list nesting accepted by the expression parser.
pub const MAX_EXPRESSION_NESTING: usize = 64;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExpressionError {
    #[error("packet expression is empty")]
    Empty,
    #[error("packet expression has {actual} bytes, exceeding limit {limit}")]
    SizeLimit { actual: usize, limit: usize },
    #[error("packet expression has more than {limit} layers")]
    LayerLimit { limit: usize },
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
    #[error("could not construct layer {name} at index {layer}: {source}")]
    Layer {
        layer: usize,
        name: String,
        #[source]
        source: CodecError,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpressionOptions {
    pub max_bytes: usize,
    pub max_layers: usize,
    pub max_nesting: usize,
}

impl Default for ExpressionOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_EXPRESSION_BYTES,
            max_layers: crate::build::DEFAULT_MAX_LAYERS,
            max_nesting: MAX_EXPRESSION_NESTING,
        }
    }
}

pub fn parse_packet_expression(
    input: &str,
    registry: &ProtocolRegistry,
    options: ExpressionOptions,
) -> Result<Packet, ExpressionError> {
    if input.trim().is_empty() {
        return Err(ExpressionError::Empty);
    }
    if input.len() > options.max_bytes {
        return Err(ExpressionError::SizeLimit {
            actual: input.len(),
            limit: options.max_bytes,
        });
    }
    if options.max_nesting > MAX_EXPRESSION_NESTING {
        return Err(ExpressionError::InvalidNestingLimit {
            value: options.max_nesting,
            maximum: MAX_EXPRESSION_NESTING,
        });
    }
    // Enforce the layer ceiling while scanning instead of first collecting
    // every slash-delimited slice. Otherwise a delimiter-heavy expression
    // can amplify a small byte budget into a much larger temporary vector
    // even when the caller allows only a handful of layers.
    let segments = split_top_level_bounded(input, '/', Some(options.max_layers))?;
    let mut packet = Packet::with_capacity(segments.len());
    for (layer_index, segment) in segments.into_iter().enumerate() {
        let (name, fields) = parse_layer(segment, layer_index, options.max_nesting)?;
        let codec =
            registry
                .codec_named(&name)
                .ok_or_else(|| ExpressionError::UnknownProtocol {
                    layer: layer_index,
                    name: name.clone(),
                })?;
        let layer = codec
            .make_layer(&fields)
            .map_err(|source| ExpressionError::Layer {
                layer: layer_index,
                name: name.clone(),
                source,
            })?;
        layer
            .validate_required_fields()
            .map_err(|source| ExpressionError::Layer {
                layer: layer_index,
                name,
                source: CodecError::Field(source),
            })?;
        packet.push_boxed(layer);
    }
    Ok(packet)
}

fn parse_layer(
    segment: &str,
    layer: usize,
    max_nesting: usize,
) -> Result<(String, BTreeMap<String, FieldValue>), ExpressionError> {
    let segment = segment.trim();
    if segment.is_empty() {
        return Err(ExpressionError::Syntax {
            offset: 0,
            message: "empty layer".to_owned(),
        });
    }
    let Some(open) = segment.find('(') else {
        return Ok((segment.to_ascii_lowercase(), BTreeMap::new()));
    };
    if !segment.ends_with(')') {
        return Err(ExpressionError::Syntax {
            offset: open,
            message: "layer arguments must end with ')'".to_owned(),
        });
    }
    let name = segment[..open].trim().to_ascii_lowercase();
    if name.is_empty() {
        return Err(ExpressionError::Syntax {
            offset: 0,
            message: "missing protocol name".to_owned(),
        });
    }
    let arguments = &segment[open + 1..segment.len() - 1];
    let mut fields = BTreeMap::new();
    if arguments.trim().is_empty() {
        return Ok((name, fields));
    }
    for argument in split_top_level_bounded(arguments, ',', None)? {
        let Some((field, raw_value)) = split_assignment(argument)? else {
            return Err(ExpressionError::Syntax {
                offset: 0,
                message: format!("expected field=value, got {argument}"),
            });
        };
        let field = field.trim().to_ascii_lowercase();
        if field.is_empty() {
            return Err(ExpressionError::Syntax {
                offset: 0,
                message: "empty field name".to_owned(),
            });
        }
        let value = parse_value_bounded(raw_value.trim(), 0, max_nesting)?;
        if fields.insert(field.clone(), value).is_some() {
            return Err(ExpressionError::DuplicateField { layer, field });
        }
    }
    Ok((name, fields))
}

fn parse_value_bounded(
    input: &str,
    depth: usize,
    max_nesting: usize,
) -> Result<FieldValue, ExpressionError> {
    if input.is_empty() {
        return Err(ExpressionError::Syntax {
            offset: 0,
            message: "missing field value".to_owned(),
        });
    }
    if input.starts_with('"') {
        return parse_quoted(input).map(FieldValue::Text);
    }
    if input.starts_with('[') {
        if depth >= max_nesting {
            return Err(ExpressionError::NestingLimit { limit: max_nesting });
        }
        if !input.ends_with(']') {
            return Err(ExpressionError::Syntax {
                offset: 0,
                message: "unterminated list".to_owned(),
            });
        }
        let body = &input[1..input.len() - 1];
        if body.trim().is_empty() {
            return Ok(FieldValue::List(Vec::new()));
        }
        let values = split_top_level_bounded(body, ',', None)?
            .into_iter()
            .map(|value| parse_value_bounded(value.trim(), depth + 1, max_nesting))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(FieldValue::List(values));
    }
    if input.eq_ignore_ascii_case("true") {
        return Ok(FieldValue::Bool(true));
    }
    if input.eq_ignore_ascii_case("false") {
        return Ok(FieldValue::Bool(false));
    }
    if let Ok(value) = Ipv4Addr::from_str(input) {
        return Ok(FieldValue::Ipv4(value));
    }
    if let Ok(value) = Ipv6Addr::from_str(input) {
        return Ok(FieldValue::Ipv6(value));
    }
    if let Some(value) = strip_hex_prefix(input) {
        let parsed = u64::from_str_radix(value, 16).map_err(|_| ExpressionError::Syntax {
            offset: 0,
            message: format!("invalid hexadecimal integer {input}"),
        })?;
        return Ok(FieldValue::Unsigned(parsed));
    }
    if let Ok(value) = input.parse::<u64>() {
        return Ok(FieldValue::Unsigned(value));
    }
    if let Ok(value) = input.parse::<i64>() {
        return Ok(FieldValue::Signed(value));
    }
    if let Some(mac) = parse_mac(input) {
        return Ok(FieldValue::Mac(mac));
    }
    Ok(FieldValue::Text(input.to_owned()))
}

fn parse_quoted(input: &str) -> Result<String, ExpressionError> {
    if input.len() < 2 || !input.ends_with('"') {
        return Err(ExpressionError::Syntax {
            offset: 0,
            message: "unterminated quoted string".to_owned(),
        });
    }
    let mut output = String::new();
    let mut escaped = false;
    for (offset, character) in input[1..input.len() - 1].char_indices() {
        if escaped {
            output.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '"' => '"',
                '\\' => '\\',
                other => {
                    return Err(ExpressionError::Syntax {
                        offset: offset + 1,
                        message: format!("unsupported escape `\\{other}`"),
                    });
                }
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Err(ExpressionError::Syntax {
                offset: offset + 1,
                message: "unescaped quote in quoted string".to_owned(),
            });
        } else {
            output.push(character);
        }
    }
    if escaped {
        return Err(ExpressionError::Syntax {
            offset: input.len() - 1,
            message: "trailing escape".to_owned(),
        });
    }
    Ok(output)
}

fn split_assignment(input: &str) -> Result<Option<(&str, &str)>, ExpressionError> {
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0usize;
    for (offset, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if quoted {
            continue;
        }
        match character {
            '[' | '(' => depth += 1,
            ']' | ')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| ExpressionError::Syntax {
                        offset,
                        message: "unbalanced delimiter".to_owned(),
                    })?;
            }
            '=' if depth == 0 => return Ok(Some((&input[..offset], &input[offset + 1..]))),
            _ => {}
        }
    }
    Ok(None)
}

fn split_top_level_bounded(
    input: &str,
    delimiter: char,
    maximum_parts: Option<usize>,
) -> Result<Vec<&str>, ExpressionError> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut paren_depth = 0usize;
    let mut list_depth = 0usize;
    for (offset, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if quoted {
            continue;
        }
        match character {
            '(' => paren_depth += 1,
            ')' => {
                paren_depth =
                    paren_depth
                        .checked_sub(1)
                        .ok_or_else(|| ExpressionError::Syntax {
                            offset,
                            message: "unexpected ')'".to_owned(),
                        })?;
            }
            '[' => list_depth += 1,
            ']' => {
                list_depth = list_depth
                    .checked_sub(1)
                    .ok_or_else(|| ExpressionError::Syntax {
                        offset,
                        message: "unexpected ']'".to_owned(),
                    })?;
            }
            _ if character == delimiter && paren_depth == 0 && list_depth == 0 => {
                if let Some(maximum) =
                    maximum_parts.filter(|maximum| result.len() >= maximum.saturating_sub(1))
                {
                    return Err(ExpressionError::LayerLimit { limit: maximum });
                }
                result.push(&input[start..offset]);
                start = offset + character.len_utf8();
            }
            _ => {}
        }
    }
    if quoted || paren_depth != 0 || list_depth != 0 {
        return Err(ExpressionError::Syntax {
            offset: input.len(),
            message: "unterminated quote or delimiter".to_owned(),
        });
    }
    if let Some(maximum) = maximum_parts.filter(|maximum| result.len() >= *maximum) {
        return Err(ExpressionError::LayerLimit { limit: maximum });
    }
    result.push(&input[start..]);
    Ok(result)
}

fn strip_hex_prefix(input: &str) -> Option<&str> {
    input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
}

pub fn decode_hex(input: &str) -> Result<Bytes, CodecError> {
    let protocol = crate::layer::ProtocolId::new("raw");
    let compact = strip_hex_prefix(input)
        .unwrap_or(input)
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && *character != ':' && *character != '-'
        })
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return Err(CodecError::Invalid {
            protocol,
            message: "hex value must contain an even number of digits".to_owned(),
        });
    }
    let digits = compact.as_bytes();
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for offset in (0..digits.len()).step_by(2) {
        let high = hex_nibble(digits[offset]).ok_or_else(|| CodecError::Invalid {
            protocol: protocol.clone(),
            message: format!("invalid hex at byte {offset}"),
        })?;
        let low = hex_nibble(digits[offset + 1]).ok_or_else(|| CodecError::Invalid {
            protocol: protocol.clone(),
            message: format!("invalid hex at byte {}", offset + 1),
        })?;
        bytes.push((high << 4) | low);
    }
    Ok(Bytes::from(bytes))
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
