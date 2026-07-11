// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use bytes::Bytes;
use thiserror::Error;

use super::packet::Packet;
use super::registry::{CodecError, ProtocolRegistry};
use super::value::FieldValue;

pub const DEFAULT_MAX_EXPRESSION_BYTES: usize = 1024 * 1024;

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
            max_layers: super::build::DEFAULT_MAX_LAYERS,
            max_nesting: 64,
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
    let segments = split_top_level(input, '/')?;
    if segments.len() > options.max_layers {
        return Err(ExpressionError::LayerLimit {
            limit: options.max_layers,
        });
    }
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
                name,
                source,
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
    for argument in split_top_level(arguments, ',')? {
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
        let values = split_top_level(body, ',')?
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
    if let Some(value) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
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
    for character in input[1..input.len() - 1].chars() {
        if escaped {
            output.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '"' => '"',
                '\\' => '\\',
                other => other,
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
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

fn split_top_level(input: &str, delimiter: char) -> Result<Vec<&str>, ExpressionError> {
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
    result.push(&input[start..]);
    Ok(result)
}

fn parse_mac(input: &str) -> Option<[u8; 6]> {
    let normalized = input.replace('-', ":");
    let parts = normalized.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return None;
    }
    let mut output = [0u8; 6];
    for (index, part) in parts.into_iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        output[index] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(output)
}

pub fn decode_hex(input: &str) -> Result<Bytes, CodecError> {
    let protocol = super::layer::ProtocolId::new("raw");
    let compact = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_split_ignores_slashes_and_commas_in_quotes() {
        let layers = split_top_level("raw(text=\"a/b,c\")/raw()", '/').unwrap();
        assert_eq!(layers, ["raw(text=\"a/b,c\")", "raw()"]);
    }

    #[test]
    fn value_parser_handles_lists_addresses_and_mac() {
        assert!(matches!(
            parse_value_bounded("192.0.2.1", 0, 64).unwrap(),
            FieldValue::Ipv4(_)
        ));
        assert!(matches!(
            parse_value_bounded("00:11:22:33:44:55", 0, 64).unwrap(),
            FieldValue::Mac(_)
        ));
        assert!(matches!(
            parse_value_bounded("[1,2,\"three\"]", 0, 64).unwrap(),
            FieldValue::List(values) if values.len() == 3
        ));
    }

    #[test]
    fn non_ascii_hex_is_rejected_without_panicking() {
        assert!(decode_hex("0é0").is_err());
        assert!(decode_hex("é").is_err());
    }

    #[test]
    fn expression_list_nesting_is_bounded() {
        let registry = ProtocolRegistry::builder().build().unwrap();
        let error = parse_packet_expression(
            "raw(bytes=[[[[1]]]])",
            &registry,
            ExpressionOptions {
                max_nesting: 2,
                ..ExpressionOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(error, ExpressionError::NestingLimit { limit: 2 }));
    }
}
