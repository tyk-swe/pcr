// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compact packet expressions.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use thiserror::Error;

use crate::Packet;

use crate::field::{FieldValue, parse_mac};
use crate::registry::Registry;

const DEFAULT_MAX_EXPRESSION_BYTES: usize = 1024 * 1024;
/// Absolute recursive list nesting accepted by the expression parser.
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
    #[error("invalid value for {field} at layer {layer}: {source}")]
    Value {
        layer: usize,
        field: String,
        #[source]
        source: crate::field::CoerceError,
    },
    #[error("could not construct layer {name} at index {layer}: {source}")]
    Layer {
        layer: usize,
        name: String,
        #[source]
        source: crate::codec::Error,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub max_bytes: usize,
    pub max_layers: usize,
    pub max_nesting: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_EXPRESSION_BYTES,
            max_layers: crate::build::DEFAULT_MAX_LAYERS,
            max_nesting: MAX_EXPRESSION_NESTING,
        }
    }
}

pub fn parse(input: &str, registry: &Registry, options: Options) -> Result<Packet, Error> {
    if input.trim().is_empty() {
        return Err(Error::Empty);
    }
    if input.len() > options.max_bytes {
        return Err(Error::SizeLimit {
            actual: input.len(),
            limit: options.max_bytes,
        });
    }
    if options.max_nesting > MAX_EXPRESSION_NESTING {
        return Err(Error::InvalidNestingLimit {
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
        let (name, arguments) = parse_layer_header(segment)?;
        let codec = registry
            .codec_named(&name)
            .ok_or_else(|| Error::UnknownProtocol {
                layer: layer_index,
                name: name.clone(),
            })?;
        let schema = registry
            .schema(&codec.protocol_id())
            .or_else(|| codec.published_schema());
        let fields = parse_layer_fields(arguments, layer_index, options.max_nesting, schema)?;
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

fn parse_layer_header(segment: &str) -> Result<(String, &str), Error> {
    let segment = segment.trim();
    if segment.is_empty() {
        return Err(Error::Syntax {
            offset: 0,
            message: "empty layer".to_owned(),
        });
    }
    let Some(open) = segment.find('(') else {
        let name = segment.to_ascii_lowercase();
        if name.is_empty() {
            return Err(Error::Syntax {
                offset: 0,
                message: "missing protocol name".to_owned(),
            });
        }
        return Ok((name, ""));
    };
    if !segment.ends_with(')') {
        return Err(Error::Syntax {
            offset: open,
            message: "layer arguments must end with ')'".to_owned(),
        });
    }
    let name = segment
        .get(..open)
        .map(str::trim)
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.is_empty() {
        return Err(Error::Syntax {
            offset: 0,
            message: "missing protocol name".to_owned(),
        });
    }
    let arguments = segment
        .get(open.saturating_add(1)..segment.len().saturating_sub(1))
        .unwrap_or("");
    Ok((name, arguments))
}

fn parse_layer_fields(
    arguments: &str,
    layer: usize,
    max_nesting: usize,
    schema: Option<&crate::layer::Schema>,
) -> Result<BTreeMap<String, FieldValue>, Error> {
    let mut fields = BTreeMap::new();
    if arguments.trim().is_empty() {
        return Ok(fields);
    }
    let protocol_id = schema.map(|s| &s.protocol);
    for argument in split_top_level_bounded(arguments, ',', None)? {
        let Some((field, raw_value)) = split_assignment(argument)? else {
            return Err(Error::Syntax {
                offset: 0,
                message: format!("expected field=value, got {argument}"),
            });
        };
        let field = field.trim().to_ascii_lowercase();
        if field.is_empty() {
            return Err(Error::Syntax {
                offset: 0,
                message: "empty field name".to_owned(),
            });
        }
        let raw_value = raw_value.trim();
        let field_schema = schema.and_then(|s| {
            s.fields
                .iter()
                .find(|declared| declared.name.eq_ignore_ascii_case(&field))
        });
        let value = parse_field_value(
            raw_value,
            field_schema,
            layer,
            &field,
            max_nesting,
            protocol_id,
        )?;
        if fields.insert(field.clone(), value).is_some() {
            return Err(Error::DuplicateField { layer, field });
        }
    }
    Ok(fields)
}

fn parse_field_value(
    input: &str,
    field_schema: Option<&crate::layer::FieldSchema>,
    layer: usize,
    field_name: &str,
    max_nesting: usize,
    protocol_id: Option<&crate::layer::Id>,
) -> Result<FieldValue, Error> {
    if input.is_empty() {
        return Err(Error::Syntax {
            offset: 0,
            message: "missing field value".to_owned(),
        });
    }
    if input.starts_with('"') {
        return parse_quoted(input).map(FieldValue::Text);
    }
    if input.starts_with('[') {
        if let Some(schema) = field_schema
            && schema.kind != crate::field::FieldKind::List
        {
            return Err(Error::Syntax {
                offset: 0,
                message: format!("field {field_name} does not accept a list"),
            });
        }
        return parse_list_bounded(input, 0, max_nesting);
    }
    if let Some(hex_str) = input.strip_prefix("raw:") {
        if field_schema.is_some_and(|schema| schema.derived) {
            return crate::field::coerce_kind(
                crate::field::FieldKind::Bytes,
                None,
                None,
                false,
                hex_str,
            )
            .map_err(|source| Error::Value {
                layer,
                field: field_name.to_owned(),
                source,
            });
        }
        return Err(Error::Syntax {
            offset: 0,
            message: format!("`raw:` is only valid on a derived field, got `{field_name}`"),
        });
    }
    if let Some(schema) = field_schema {
        return crate::field::coerce(schema, input).map_err(|source| Error::Value {
            layer,
            field: field_name.to_owned(),
            source,
        });
    }
    if protocol_id.is_some_and(|p| p.as_str() == "raw" || p.as_str() == "padding")
        && (field_name == "text" || field_name == "hex")
    {
        return crate::field::coerce_kind(crate::field::FieldKind::Text, None, None, false, input)
            .map_err(|source| Error::Value {
                layer,
                field: field_name.to_owned(),
                source,
            });
    }
    parse_value_bounded(input, 0, max_nesting)
}

fn parse_list_bounded(input: &str, depth: usize, max_nesting: usize) -> Result<FieldValue, Error> {
    if depth >= max_nesting {
        return Err(Error::NestingLimit { limit: max_nesting });
    }
    if !input.ends_with(']') {
        return Err(Error::Syntax {
            offset: 0,
            message: "unterminated list".to_owned(),
        });
    }
    let body = input.get(1..input.len().saturating_sub(1)).unwrap_or("");
    if body.trim().is_empty() {
        return Ok(FieldValue::List(Vec::new()));
    }
    let values = split_top_level_bounded(body, ',', None)?
        .into_iter()
        .map(|value| parse_value_bounded(value.trim(), depth.saturating_add(1), max_nesting))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FieldValue::List(values))
}

#[cfg(test)]
fn parse_layer(
    segment: &str,
    layer: usize,
    max_nesting: usize,
) -> Result<(String, BTreeMap<String, FieldValue>), Error> {
    let (name, arguments) = parse_layer_header(segment)?;
    let fields = parse_layer_fields(arguments, layer, max_nesting, None)?;
    Ok((name, fields))
}

fn parse_value_bounded(input: &str, depth: usize, max_nesting: usize) -> Result<FieldValue, Error> {
    if input.is_empty() {
        return Err(Error::Syntax {
            offset: 0,
            message: "missing field value".to_owned(),
        });
    }
    if input.starts_with('"') {
        return parse_quoted(input).map(FieldValue::Text);
    }
    if input.starts_with('[') {
        if depth >= max_nesting {
            return Err(Error::NestingLimit { limit: max_nesting });
        }
        if !input.ends_with(']') {
            return Err(Error::Syntax {
                offset: 0,
                message: "unterminated list".to_owned(),
            });
        }
        let body = &input[1..input.len().saturating_sub(1)];
        if body.trim().is_empty() {
            return Ok(FieldValue::List(Vec::new()));
        }
        let values = split_top_level_bounded(body, ',', None)?
            .into_iter()
            .map(|value| parse_value_bounded(value.trim(), depth.saturating_add(1), max_nesting))
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
        let parsed = u64::from_str_radix(value, 16).map_err(|_| Error::Syntax {
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

fn parse_quoted(input: &str) -> Result<String, Error> {
    if input.len() < 2 || !input.ends_with('"') {
        return Err(Error::Syntax {
            offset: 0,
            message: "unterminated quoted string".to_owned(),
        });
    }
    let mut output = String::new();
    let mut escaped = false;
    for (offset, character) in input[1..input.len().saturating_sub(1)].char_indices() {
        if escaped {
            output.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '"' => '"',
                '\\' => '\\',
                other => {
                    return Err(Error::Syntax {
                        offset: offset.saturating_add(1),
                        message: format!("unsupported escape `\\{other}`"),
                    });
                }
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Err(Error::Syntax {
                offset: offset.saturating_add(1),
                message: "unescaped quote in quoted string".to_owned(),
            });
        } else {
            output.push(character);
        }
    }
    if escaped {
        return Err(Error::Syntax {
            offset: input.len().saturating_sub(1),
            message: "trailing escape".to_owned(),
        });
    }
    Ok(output)
}

fn split_assignment(input: &str) -> Result<Option<(&str, &str)>, Error> {
    let mut scanner = TopLevelScanner::merging_brackets(input);
    loop {
        match scanner.next_top_level() {
            Ok(Some((offset, '='))) => {
                return Ok(Some((&input[..offset], &input[offset.saturating_add(1)..])));
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(ScanFailure::Unterminated) => return Ok(None),
            Err(ScanFailure::Unbalanced { offset, .. }) => {
                return Err(Error::Syntax {
                    offset,
                    message: "unbalanced delimiter".to_owned(),
                });
            }
        }
    }
}

fn split_top_level_bounded(
    input: &str,
    delimiter: char,
    maximum_parts: Option<usize>,
) -> Result<Vec<&str>, Error> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut scanner = TopLevelScanner::new(input);
    while let Some((offset, character)) = match scanner.next_top_level() {
        Ok(next) => next,
        Err(ScanFailure::Unbalanced { offset, character }) => {
            return Err(Error::Syntax {
                offset,
                message: format!("unexpected '{character}'"),
            });
        }
        Err(ScanFailure::Unterminated) => {
            return Err(Error::Syntax {
                offset: input.len(),
                message: "unterminated quote or delimiter".to_owned(),
            });
        }
    } {
        if character != delimiter {
            continue;
        }
        if let Some(maximum) =
            maximum_parts.filter(|maximum| result.len() >= maximum.saturating_sub(1))
        {
            return Err(Error::LayerLimit { limit: maximum });
        }
        result.push(&input[start..offset]);
        start = offset.saturating_add(character.len_utf8());
    }
    if let Some(maximum) = maximum_parts.filter(|maximum| result.len() >= *maximum) {
        return Err(Error::LayerLimit { limit: maximum });
    }
    result.push(&input[start..]);
    Ok(result)
}

/// Walks input while tracking quotes, escapes, and bracket nesting.
///
/// `merge_brackets` treats `(`/`[` and `)`/`]` as one shared depth, matching
/// the assignment scanner's historical behavior; the splitter keeps the depths
/// separate so a mismatched bracket reports the offending character.
struct TopLevelScanner<'a> {
    chars: std::str::CharIndices<'a>,
    quoted: bool,
    escaped: bool,
    paren_depth: usize,
    list_depth: usize,
    merge_brackets: bool,
}

impl<'a> TopLevelScanner<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.char_indices(),
            quoted: false,
            escaped: false,
            paren_depth: 0,
            list_depth: 0,
            merge_brackets: false,
        }
    }

    fn merging_brackets(input: &'a str) -> Self {
        Self {
            merge_brackets: true,
            ..Self::new(input)
        }
    }

    fn next_top_level(&mut self) -> Result<Option<(usize, char)>, ScanFailure> {
        for (offset, character) in self.chars.by_ref() {
            if self.escaped {
                self.escaped = false;
                continue;
            }
            if self.quoted && character == '\\' {
                self.escaped = true;
                continue;
            }
            if character == '"' {
                self.quoted = !self.quoted;
                continue;
            }
            if self.quoted {
                continue;
            }
            let unbalanced = |character| ScanFailure::Unbalanced { offset, character };
            match character {
                '(' => self.paren_depth = self.paren_depth.saturating_add(1),
                ')' => {
                    let Some(depth) = self.paren_depth.checked_sub(1) else {
                        return Err(unbalanced(character));
                    };
                    self.paren_depth = depth;
                }
                '[' => {
                    if self.merge_brackets {
                        self.paren_depth = self.paren_depth.saturating_add(1);
                    } else {
                        self.list_depth = self.list_depth.saturating_add(1);
                    }
                }
                ']' => {
                    let depth = if self.merge_brackets {
                        &mut self.paren_depth
                    } else {
                        &mut self.list_depth
                    };
                    let Some(remaining) = depth.checked_sub(1) else {
                        return Err(unbalanced(character));
                    };
                    *depth = remaining;
                }
                _ if self.paren_depth == 0 && self.list_depth == 0 => {
                    return Ok(Some((offset, character)));
                }
                _ => {}
            }
        }
        if self.quoted || self.paren_depth != 0 || self.list_depth != 0 {
            Err(ScanFailure::Unterminated)
        } else {
            Ok(None)
        }
    }
}

/// A structural failure found by [`TopLevelScanner`].
enum ScanFailure {
    /// A closing bracket appeared without a matching opener.
    Unbalanced { offset: usize, character: char },
    /// A quote or bracket was still open at the end of the input.
    Unterminated,
}

fn strip_hex_prefix(input: &str) -> Option<&str> {
    input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn value_parser_distinguishes_addresses_numbers_macs_lists_and_text() {
        let cases = [
            ("TRUE", FieldValue::Bool(true)),
            ("false", FieldValue::Bool(false)),
            ("192.0.2.1", FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            (
                "2001:db8::1",
                FieldValue::Ipv6("2001:db8::1".parse().expect("fixture address")),
            ),
            ("0Xff", FieldValue::Unsigned(255)),
            ("18446744073709551615", FieldValue::Unsigned(u64::MAX)),
            ("-42", FieldValue::Signed(-42)),
            (
                "00:11:22:33:44:55",
                FieldValue::Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ),
            ("service-name", FieldValue::Text("service-name".to_owned())),
            (
                "[1, [true, 192.0.2.1]]",
                FieldValue::List(vec![
                    FieldValue::Unsigned(1),
                    FieldValue::List(vec![
                        FieldValue::Bool(true),
                        FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                    ]),
                ]),
            ),
        ];

        for (source, expected) in cases {
            assert_eq!(
                parse_value_bounded(source, 0, 8).unwrap(),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn quoted_values_decode_supported_escapes_and_reject_ambiguous_strings() {
        assert_eq!(
            parse_quoted(r#""line\nreturn\rindent\tquote\"slash\\""#).unwrap(),
            "line\nreturn\rindent\tquote\"slash\\"
        );

        for (source, expected) in [
            (r#""unterminated"#, "unterminated quoted string"),
            (r#""bad\q""#, "unsupported escape `\\q`"),
            (r#""a"b""#, "unescaped quote in quoted string"),
            (r#""tail\""#, "trailing escape"),
        ] {
            let error = parse_quoted(source).expect_err(source);
            assert!(error.to_string().contains(expected), "{source}: {error}");
        }
    }

    #[test]
    fn top_level_splitting_ignores_nested_and_quoted_delimiters() {
        assert_eq!(
            split_top_level_bounded(r#"alpha(value="x/y")/beta(values=[1,2])"#, '/', None).unwrap(),
            [r#"alpha(value="x/y")"#, "beta(values=[1,2])"]
        );
        assert_eq!(
            split_top_level_bounded(r#"a="x=y",b=[1,2]"#, ',', None).unwrap(),
            [r#"a="x=y""#, "b=[1,2]"]
        );
        assert!(matches!(
            split_top_level_bounded("a/b", '/', Some(1)),
            Err(Error::LayerLimit { limit: 1 })
        ));
        assert!(matches!(
            split_top_level_bounded("a]", '/', None),
            Err(Error::Syntax { offset: 1, .. })
        ));
        assert!(matches!(
            split_top_level_bounded("a([", '/', None),
            Err(Error::Syntax { offset: 3, .. })
        ));
    }

    #[test]
    fn layer_arguments_reject_duplicates_missing_values_and_unbalanced_delimiters() {
        let (name, fields) = parse_layer(
            r#"TCP(source_port=1, options=[1, [2, 3]], label="a,b")"#,
            4,
            8,
        )
        .unwrap();
        assert_eq!(name, "tcp");
        assert_eq!(fields.len(), 3);

        let duplicate = parse_layer("tcp(source_port=1,SOURCE_PORT=2)", 4, 8).unwrap_err();
        assert!(matches!(
            duplicate,
            Error::DuplicateField {
                layer: 4,
                ref field
            } if field == "source_port"
        ));

        for (source, expected) in [
            ("", "empty layer"),
            ("(field=1)", "missing protocol name"),
            ("tcp(field=1", "arguments must end"),
            ("tcp(field)", "expected field=value"),
            ("tcp(=1)", "empty field name"),
            ("tcp(field=)", "missing field value"),
            ("tcp(field=[1,2)", "unterminated quote or delimiter"),
        ] {
            let error = parse_layer(source, 0, 8).expect_err(source);
            assert!(error.to_string().contains(expected), "{source}: {error}");
        }
    }

    #[test]
    fn expression_limits_and_registry_failures_report_the_exact_boundary() {
        let registry = crate::protocol::builtin::registry().expect("built-in registry");

        assert!(matches!(
            parse(" ", &registry, Options::default()),
            Err(Error::Empty)
        ));
        assert!(matches!(
            parse(
                "ipv4",
                &registry,
                Options {
                    max_bytes: 3,
                    ..Options::default()
                }
            ),
            Err(Error::SizeLimit {
                actual: 4,
                limit: 3
            })
        ));
        assert!(matches!(
            parse(
                "ipv4",
                &registry,
                Options {
                    max_nesting: MAX_EXPRESSION_NESTING + 1,
                    ..Options::default()
                }
            ),
            Err(Error::InvalidNestingLimit { .. })
        ));
        assert!(matches!(
            parse(
                "ipv4/udp",
                &registry,
                Options {
                    max_layers: 1,
                    ..Options::default()
                }
            ),
            Err(Error::LayerLimit { limit: 1 })
        ));
        assert!(matches!(
            parse("unknown_fixture", &registry, Options::default()),
            Err(Error::UnknownProtocol { layer: 0, .. })
        ));
        // packet/v2 coercion
        assert!(matches!(
            parse("ipv4(source=not-an-address)", &registry, Options::default()),
            Err(Error::Value {
                layer: 0,
                ref field,
                ..
            }) if field == "source"
        ));
    }

    #[test]
    fn recursive_list_limit_is_checked_before_descending() {
        assert_eq!(
            parse_value_bounded("[]", 0, 1).unwrap(),
            FieldValue::List(Vec::new())
        );
        assert!(matches!(
            parse_value_bounded("[]", 0, 0),
            Err(Error::NestingLimit { limit: 0 })
        ));
        assert!(matches!(
            parse_value_bounded("[[1]]", 0, 1),
            Err(Error::NestingLimit { limit: 1 })
        ));
        assert!(matches!(
            parse_value_bounded("[1", 0, 8),
            Err(Error::Syntax { .. })
        ));
        assert!(matches!(
            parse_value_bounded("0xgg", 0, 8),
            Err(Error::Syntax { .. })
        ));
    }
}
