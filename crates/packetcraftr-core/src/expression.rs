// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use thiserror::Error;

use crate::packet::Packet;

use crate::error::{Classification, Classified, Kind};
use crate::field::{FieldValue, parse_mac};
use crate::registry::Registry;

const DEFAULT_MAX_EXPRESSION_BYTES: usize = 1024 * 1024;
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
            | Self::NestingLimit { .. }
            | Self::InvalidNestingLimit { .. } => Classification::new(
                "cli.expression_limit",
                Kind::Usage,
                Some("shorten the expression to stay inside its byte, layer, and nesting bounds"),
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
/// [`validate`](Self::validate) enforces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_layers: usize,
    pub max_nesting: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_EXPRESSION_BYTES,
            max_layers: crate::packet::DEFAULT_MAX_LAYERS,
            max_nesting: MAX_EXPRESSION_NESTING,
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
    for (layer_index, (base, segment)) in segments.into_iter().enumerate() {
        let (name, fields) = parse_layer(base, segment, layer_index, limits.max_nesting)?;
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
    parse_value_bounded(0, input, 0, limits.max_nesting)
}

fn parse_layer(
    base: usize,
    segment: &str,
    layer: usize,
    max_nesting: usize,
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
        let value = parse_value_bounded(value_base, raw_value, 0, max_nesting)?;
        if fields.insert(field.clone(), value).is_some() {
            return Err(Error::DuplicateField { layer, field });
        }
    }
    Ok((name, fields))
}

fn parse_value_bounded(
    base: usize,
    input: &str,
    depth: usize,
    max_nesting: usize,
) -> Result<FieldValue, Error> {
    let (base, input) = trim_at(base, input);
    if input.is_empty() {
        return Err(Error::Syntax {
            offset: base,
            message: "missing field value".to_owned(),
        });
    }
    for (prefix, hexadecimal) in [("hex(", true), ("bytes(", false)] {
        if let Some(body) = input.strip_prefix(prefix) {
            return parse_byte_literal(base, prefix.len(), body, hexadecimal);
        }
    }
    if input.starts_with('"') {
        return parse_quoted(base, input).map(FieldValue::Text);
    }
    if input.starts_with('{') {
        return parse_object(base, input, depth, max_nesting);
    }
    if input.starts_with('[') {
        return parse_list(base, input, depth, max_nesting);
    }
    parse_scalar(base, input)
}

fn parse_byte_literal(
    base: usize,
    prefix_len: usize,
    body: &str,
    hexadecimal: bool,
) -> Result<FieldValue, Error> {
    let body = body.strip_suffix(')').ok_or_else(|| Error::Syntax {
        offset: base,
        message: "unterminated byte literal".to_owned(),
    })?;
    let (text_base, quoted) = trim_at(base.saturating_add(prefix_len), body);
    let text = parse_quoted(text_base, quoted)?;
    if !hexadecimal {
        return Ok(FieldValue::Bytes(text.into()));
    }
    let bytes = decode_hex_pairs(&text).ok_or_else(|| Error::Syntax {
        offset: text_base,
        message: "hex literal requires pairs of hexadecimal digits".to_owned(),
    })?;
    Ok(FieldValue::Bytes(bytes.into()))
}

fn decode_hex_pairs(text: &str) -> Option<Vec<u8>> {
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let digit = |byte: u8| {
        char::from(byte)
            .to_digit(16)
            .and_then(|value| u8::try_from(value).ok())
    };
    let mut bytes = Vec::with_capacity(pairs.len());
    for &[high, low] in pairs {
        bytes.push((digit(high)? << 4) | digit(low)?);
    }
    Some(bytes)
}

fn parse_object(
    base: usize,
    input: &str,
    depth: usize,
    max_nesting: usize,
) -> Result<FieldValue, Error> {
    let body = enclosed_body(base, input, '}', "unterminated object", depth, max_nesting)?;
    let mut values = BTreeMap::new();
    if body.trim().is_empty() {
        return Ok(FieldValue::Object(values));
    }
    for (entry_base, entry) in split_top_level_bounded(base.saturating_add(1), body, ',', None)? {
        let Some((name, (value_base, value))) = split_assignment(entry_base, entry) else {
            return Err(Error::Syntax {
                offset: trim_at(entry_base, entry).0,
                message: "expected object field=value".to_owned(),
            });
        };
        let (name_base, name) = trim_at(entry_base, name);
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Error::Syntax {
                offset: name_base,
                message: "invalid object field name".to_owned(),
            });
        }
        let value = parse_value_bounded(value_base, value, depth.saturating_add(1), max_nesting)?;
        if values.insert(name.to_owned(), value).is_some() {
            return Err(Error::Syntax {
                offset: name_base,
                message: format!("duplicate object field {name}"),
            });
        }
    }
    Ok(FieldValue::Object(values))
}

fn parse_list(
    base: usize,
    input: &str,
    depth: usize,
    max_nesting: usize,
) -> Result<FieldValue, Error> {
    let body = enclosed_body(base, input, ']', "unterminated list", depth, max_nesting)?;
    if body.trim().is_empty() {
        return Ok(FieldValue::List(Vec::new()));
    }
    let values = split_top_level_bounded(base.saturating_add(1), body, ',', None)?
        .into_iter()
        .map(|(value_base, value)| {
            parse_value_bounded(value_base, value, depth.saturating_add(1), max_nesting)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FieldValue::List(values))
}

/// Checks the nesting budget, then strips the opening delimiter (already known
/// to be one ASCII byte) and `close` from `input`.
fn enclosed_body<'a>(
    base: usize,
    input: &'a str,
    close: char,
    unterminated: &str,
    depth: usize,
    max_nesting: usize,
) -> Result<&'a str, Error> {
    if depth >= max_nesting {
        return Err(Error::NestingLimit { limit: max_nesting });
    }
    input[1..].strip_suffix(close).ok_or_else(|| Error::Syntax {
        offset: base,
        message: unterminated.to_owned(),
    })
}

fn parse_scalar(base: usize, input: &str) -> Result<FieldValue, Error> {
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
    if let Some(digits) = strip_hex_prefix(input) {
        let invalid = || Error::Syntax {
            offset: base,
            message: format!("invalid hexadecimal integer {input}"),
        };
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        let parsed = u64::from_str_radix(digits, 16).map_err(|_| invalid())?;
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

fn parse_quoted(base: usize, input: &str) -> Result<String, Error> {
    if input.len() < 2 || !input.starts_with('"') || !input.ends_with('"') {
        return Err(Error::Syntax {
            offset: base,
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
                        offset: base.saturating_add(offset).saturating_add(1),
                        message: format!("unsupported escape `\\{other}`"),
                    });
                }
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Err(Error::Syntax {
                offset: base.saturating_add(offset).saturating_add(1),
                message: "unescaped quote in quoted string".to_owned(),
            });
        } else {
            output.push(character);
        }
    }
    if escaped {
        return Err(Error::Syntax {
            offset: base.saturating_add(input.len().saturating_sub(1)),
            message: "trailing escape".to_owned(),
        });
    }
    Ok(output)
}

type Assignment<'a> = (&'a str, (usize, &'a str));

/// Callers pass elements that `split_top_level_bounded` already balance-checked,
/// so the scan cannot fail.
fn split_assignment(base: usize, input: &str) -> Option<Assignment<'_>> {
    let mut scanner = TopLevelScanner::new(input);
    while let Ok(Some((offset, character))) = scanner.next_top_level() {
        if character == '=' {
            let value = offset.saturating_add(1);
            return Some((
                &input[..offset],
                (base.saturating_add(value), &input[value..]),
            ));
        }
    }
    None
}

fn split_top_level_bounded(
    base: usize,
    input: &str,
    delimiter: char,
    maximum_parts: Option<usize>,
) -> Result<Vec<(usize, &str)>, Error> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut scanner = TopLevelScanner::new(input);
    while let Some((offset, character)) = match scanner.next_top_level() {
        Ok(next) => next,
        Err(ScanFailure::Unbalanced { offset, character }) => {
            return Err(Error::Syntax {
                offset: base.saturating_add(offset),
                message: format!("unexpected '{character}'"),
            });
        }
        Err(ScanFailure::Unterminated) => {
            return Err(Error::Syntax {
                offset: base.saturating_add(input.len()),
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
        result.push((base.saturating_add(start), &input[start..offset]));
        start = offset.saturating_add(character.len_utf8());
    }
    if let Some(maximum) = maximum_parts.filter(|maximum| result.len() >= *maximum) {
        return Err(Error::LayerLimit { limit: maximum });
    }
    result.push((base.saturating_add(start), &input[start..]));
    Ok(result)
}

fn trim_at(base: usize, text: &str) -> (usize, &str) {
    let trimmed = text.trim_start();
    let leading = text.len().saturating_sub(trimmed.len());
    (base.saturating_add(leading), trimmed.trim_end())
}

struct TopLevelScanner<'a> {
    chars: std::str::CharIndices<'a>,
    quoted: bool,
    escaped: bool,
    paren_depth: usize,
    list_depth: usize,
    object_depth: usize,
}

impl<'a> TopLevelScanner<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.char_indices(),
            quoted: false,
            escaped: false,
            paren_depth: 0,
            list_depth: 0,
            object_depth: 0,
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
                '{' => self.object_depth = self.object_depth.saturating_add(1),
                '}' => {
                    self.object_depth = self
                        .object_depth
                        .checked_sub(1)
                        .ok_or_else(|| unbalanced(character))?;
                }
                '(' => self.paren_depth = self.paren_depth.saturating_add(1),
                ')' => {
                    let Some(depth) = self.paren_depth.checked_sub(1) else {
                        return Err(unbalanced(character));
                    };
                    self.paren_depth = depth;
                }
                '[' => self.list_depth = self.list_depth.saturating_add(1),
                ']' => {
                    let Some(depth) = self.list_depth.checked_sub(1) else {
                        return Err(unbalanced(character));
                    };
                    self.list_depth = depth;
                }
                _ if self.paren_depth == 0 && self.list_depth == 0 && self.object_depth == 0 => {
                    return Ok(Some((offset, character)));
                }
                _ => {}
            }
        }
        if self.quoted || self.paren_depth != 0 || self.list_depth != 0 || self.object_depth != 0 {
            Err(ScanFailure::Unterminated)
        } else {
            Ok(None)
        }
    }
}

enum ScanFailure {
    Unbalanced { offset: usize, character: char },
    Unterminated,
}

fn strip_hex_prefix(input: &str) -> Option<&str> {
    input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
}

#[cfg(test)]
mod tests {
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
                parse_value_bounded(0, source, 0, 8).unwrap(),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn quoted_values_decode_supported_escapes_and_reject_ambiguous_strings() {
        assert_eq!(
            parse_quoted(0, r#""line\nreturn\rindent\tquote\"slash\\""#).unwrap(),
            "line\nreturn\rindent\tquote\"slash\\"
        );

        for (source, expected) in [
            (r#""unterminated"#, "unterminated quoted string"),
            (r#""bad\q""#, "unsupported escape `\\q`"),
            (r#""a"b""#, "unescaped quote in quoted string"),
            (r#""tail\""#, "trailing escape"),
        ] {
            let error = parse_quoted(0, source).expect_err(source);
            assert!(error.to_string().contains(expected), "{source}: {error}");
        }
        assert!(matches!(
            parse_quoted(10, r#""tail\""#),
            Err(Error::Syntax { offset: 16, .. })
        ));
    }

    #[test]
    fn byte_literals_require_an_opening_quote() {
        assert_eq!(
            parse_value_bounded(0, r#"bytes("abc")"#, 0, 8).unwrap(),
            FieldValue::Bytes(bytes::Bytes::from_static(b"abc"))
        );
        for source in [r#"bytes(abc")"#, r#"hex(x0a")"#, r#"bytes(a")"#] {
            let error = parse_value_bounded(0, source, 0, 8).expect_err(source);
            assert!(
                error.to_string().contains("unterminated quoted string"),
                "{source}: {error}"
            );
        }
    }

    #[test]
    fn hex_literals_decode_digit_pairs_of_either_case() {
        for (source, expected) in [
            (r#"hex("")"#, &[][..]),
            (r#"hex("0aFf")"#, &[0x0a, 0xff]),
            (r#" hex( "00Ab12" ) "#, &[0x00, 0xab, 0x12]),
        ] {
            assert_eq!(
                parse_value_bounded(0, source, 0, 8).unwrap(),
                FieldValue::Bytes(bytes::Bytes::copy_from_slice(expected)),
                "{source}"
            );
        }
        for source in [
            r#"hex("0")"#,
            r#"hex("+1")"#,
            r#"hex("0g")"#,
            "hex(\"\u{e9}\")",
        ] {
            let error = parse_value_bounded(0, source, 0, 8).expect_err(source);
            assert!(
                matches!(&error, Error::Syntax { offset: 4, message }
                    if message == "hex literal requires pairs of hexadecimal digits"),
                "{source}: {error:?}"
            );
        }
    }

    #[test]
    fn top_level_splitting_ignores_nested_and_quoted_delimiters() {
        assert_eq!(
            split_top_level_bounded(0, r#"alpha(value="x/y")/beta(values=[1,2])"#, '/', None)
                .unwrap(),
            [(0, r#"alpha(value="x/y")"#), (19, "beta(values=[1,2])")]
        );
        assert_eq!(
            split_top_level_bounded(10, r#"a="x=y",b=[1,2]"#, ',', None).unwrap(),
            [(10, r#"a="x=y""#), (18, "b=[1,2]")]
        );
        assert!(matches!(
            split_top_level_bounded(0, "a/b", '/', Some(1)),
            Err(Error::LayerLimit { limit: 1 })
        ));
        assert!(matches!(
            split_top_level_bounded(0, "a]", '/', None),
            Err(Error::Syntax { offset: 1, .. })
        ));
        assert!(matches!(
            split_top_level_bounded(10, "a]", '/', None),
            Err(Error::Syntax { offset: 11, .. })
        ));
        assert!(matches!(
            split_top_level_bounded(0, "a([", '/', None),
            Err(Error::Syntax { offset: 3, .. })
        ));
    }

    #[test]
    fn layer_arguments_reject_duplicates_missing_values_and_unbalanced_delimiters() {
        let (name, fields) = parse_layer(
            0,
            r#"TCP(source_port=1, options=[1, [2, 3]], label="a,b")"#,
            4,
            8,
        )
        .unwrap();
        assert_eq!(name, "tcp");
        assert_eq!(fields.len(), 3);

        let duplicate = parse_layer(0, "tcp(source_port=1,SOURCE_PORT=2)", 4, 8).unwrap_err();
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
            let error = parse_layer(0, source, 0, 8).expect_err(source);
            assert!(error.to_string().contains(expected), "{source}: {error}");
        }
    }

    #[test]
    fn expression_limits_and_registry_failures_report_the_exact_boundary() {
        let registry = crate::protocol::builtin::registry();

        assert!(matches!(
            parse(" ", &registry, Limits::default()),
            Err(Error::Empty)
        ));
        assert!(matches!(
            parse(
                "ipv4",
                &registry,
                Limits {
                    max_bytes: 3,
                    ..Limits::default()
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
                Limits {
                    max_nesting: MAX_EXPRESSION_NESTING + 1,
                    ..Limits::default()
                }
            ),
            Err(Error::InvalidNestingLimit { .. })
        ));
        assert!(matches!(
            parse(
                "ipv4/udp",
                &registry,
                Limits {
                    max_layers: 1,
                    ..Limits::default()
                }
            ),
            Err(Error::LayerLimit { limit: 1 })
        ));
        assert!(matches!(
            parse("unknown_fixture", &registry, Limits::default()),
            Err(Error::UnknownProtocol { layer: 0, .. })
        ));
        assert!(matches!(
            parse("ipv4(source=not-an-address)", &registry, Limits::default()),
            Err(Error::Layer { layer: 0, .. })
        ));
    }

    #[test]
    fn recursive_list_limit_is_checked_before_descending() {
        assert_eq!(
            parse_value_bounded(0, "[]", 0, 1).unwrap(),
            FieldValue::List(Vec::new())
        );
        assert!(matches!(
            parse_value_bounded(0, "[]", 0, 0),
            Err(Error::NestingLimit { limit: 0 })
        ));
        assert!(matches!(
            parse_value_bounded(0, "[[1]]", 0, 1),
            Err(Error::NestingLimit { limit: 1 })
        ));
        assert!(matches!(
            parse_value_bounded(0, "[1", 0, 8),
            Err(Error::Syntax { .. })
        ));
    }

    #[test]
    fn hexadecimal_integers_take_bare_hex_digits_only() {
        assert_eq!(
            parse_value_bounded(0, "0x40", 0, 8).unwrap(),
            FieldValue::Unsigned(64)
        );
        for source in [
            "0x",
            "0xgg",
            "0x+40",
            "0x-40",
            "0x1_0",
            "0x10000000000000000",
        ] {
            let error = parse_value_bounded(0, source, 0, 8).expect_err(source);
            assert!(
                matches!(&error, Error::Syntax { offset: 0, message }
                    if message == &format!("invalid hexadecimal integer {source}")),
                "{source}: {error:?}"
            );
        }
    }
}
