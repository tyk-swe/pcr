// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::super::field::{FieldKind, FieldValue};
use super::lexer::CompareOperator;
use super::path::FieldSpec;

/// How an unbuilt derived wire value reflects through [`FieldValue`].
const AUTO_WIRE_VALUE: &str = "auto";

/// A constant written on the right-hand side of a display-filter comparison.
///
/// Literals are recognized by shape rather than by the field they are compared
/// against, so the same spelling means the same thing everywhere it appears.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Literal {
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Text(String),
    Bytes(Bytes),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    /// An IPv4 prefix. Comparing with `==` tests containment.
    Ipv4Net(Ipv4Addr, u8),
    /// An IPv6 prefix. Comparing with `==` tests containment.
    Ipv6Net(Ipv6Addr, u8),
    Mac([u8; 6]),
}

impl fmt::Display for Literal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(value) => write!(formatter, "{value}"),
            Self::Unsigned(value) => write!(formatter, "{value}"),
            Self::Signed(value) => write!(formatter, "{value}"),
            Self::Text(value) => write!(formatter, "\"{value}\""),
            Self::Bytes(value) => {
                for (index, byte) in value.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(":")?;
                    }
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Ipv4(value) => write!(formatter, "{value}"),
            Self::Ipv6(value) => write!(formatter, "{value}"),
            Self::Ipv4Net(value, prefix) => write!(formatter, "{value}/{prefix}"),
            Self::Ipv6Net(value, prefix) => write!(formatter, "{value}/{prefix}"),
            Self::Mac(value) => {
                for (index, byte) in value.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(":")?;
                    }
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// Parses an unquoted word into a literal, or reports that it is not one.
///
/// Shapes are tried most specific first so a spelling can never be claimed by
/// a broader form: `2001:db8::1` is an address before it is a MAC, and
/// `47:45:54:20` is a byte string because it is neither.
pub(super) fn parse(word: &str) -> Option<Literal> {
    match word {
        "true" => return Some(Literal::Bool(true)),
        "false" => return Some(Literal::Bool(false)),
        _ => {}
    }
    if let Some(rest) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).ok().map(Literal::Unsigned);
    }
    if let Some((address, prefix)) = word.split_once('/') {
        let prefix: u8 = prefix.parse().ok()?;
        if let Ok(value) = address.parse::<Ipv4Addr>() {
            return (prefix <= 32).then_some(Literal::Ipv4Net(value, prefix));
        }
        let value = address.parse::<Ipv6Addr>().ok()?;
        return (prefix <= 128).then_some(Literal::Ipv6Net(value, prefix));
    }
    if let Ok(value) = word.parse::<Ipv4Addr>() {
        return Some(Literal::Ipv4(value));
    }
    if let Ok(value) = word.parse::<Ipv6Addr>() {
        return Some(Literal::Ipv6(value));
    }
    if let Some(groups) = hex_groups(word) {
        return match <[u8; 6]>::try_from(groups.as_slice()) {
            Ok(mac) => Some(Literal::Mac(mac)),
            Err(_) => Some(Literal::Bytes(Bytes::from(groups))),
        };
    }
    if let Ok(value) = word.parse::<u64>() {
        return Some(Literal::Unsigned(value));
    }
    if let Ok(value) = word.parse::<i64>() {
        return Some(Literal::Signed(value));
    }
    None
}

/// Recognizes `aa:bb:cc`-style and `aa-bb-cc`-style hex byte runs.
///
/// Requires at least two groups so a bare `ff` stays a number, and requires a
/// consistent separator so `aa:bb-cc` is not silently accepted.
fn hex_groups(word: &str) -> Option<Vec<u8>> {
    let separator = if word.contains(':') {
        ':'
    } else if word.contains('-') {
        '-'
    } else {
        return None;
    };
    if word.contains(if separator == ':' { '-' } else { ':' }) {
        return None;
    }
    let mut bytes = Vec::new();
    for group in word.split(separator) {
        if group.len() != 2 || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        bytes.push(u8::from_str_radix(group, 16).ok()?);
    }
    (bytes.len() >= 2).then_some(bytes)
}

impl Literal {
    /// Whether this literal describes a set of addresses rather than one.
    pub(super) fn is_prefix(&self) -> bool {
        matches!(self, Self::Ipv4Net(..) | Self::Ipv6Net(..))
    }
}

/// Human-readable name of a reflective field kind, for compile-time diagnostics.
pub(super) fn kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Bool => "a boolean",
        FieldKind::Unsigned => "an unsigned number",
        FieldKind::Signed => "a signed number",
        FieldKind::Text => "text",
        FieldKind::Bytes => "bytes",
        FieldKind::Ipv4 => "an IPv4 address",
        FieldKind::Ipv6 => "an IPv6 address",
        FieldKind::Mac => "a MAC address",
        FieldKind::List => "a list",
    }
}

/// Whether a literal could ever compare true against a field of this kind.
///
/// Rejecting the impossible pairings at compile time turns a filter that would
/// silently match nothing into an error naming the field and the literal.
/// Derived fields additionally reflect as `"auto"` text, so text is accepted
/// wherever a derived wire value may appear.
pub(super) fn compatible(spec: FieldSpec, literal: &Literal) -> bool {
    match spec.kind {
        FieldKind::Bool => matches!(literal, Literal::Bool(_) | Literal::Unsigned(0 | 1)),
        FieldKind::Unsigned | FieldKind::Signed => match literal {
            Literal::Unsigned(_) | Literal::Signed(_) => true,
            // An unbuilt derived field reflects as the text `auto`; that is the
            // only way text can appear on a number. Accepting text more widely
            // would let `frame.len == nope` compile and match nothing.
            Literal::Text(text) => spec.derived && text == AUTO_WIRE_VALUE,
            _ => false,
        },
        FieldKind::Text => matches!(literal, Literal::Text(_)),
        // A byte field is equally addressable as a hex run or as text. A
        // number covers the single-byte case, which has no unambiguous run
        // spelling: `raw.bytes[0:1] == 0xaa`.
        FieldKind::Bytes => match literal {
            Literal::Bytes(_) | Literal::Mac(_) | Literal::Text(_) => true,
            Literal::Unsigned(value) => *value <= u64::from(u8::MAX),
            _ => false,
        },
        FieldKind::Ipv4 => matches!(literal, Literal::Ipv4(_) | Literal::Ipv4Net(..)),
        FieldKind::Ipv6 => matches!(literal, Literal::Ipv6(_) | Literal::Ipv6Net(..)),
        FieldKind::Mac => matches!(literal, Literal::Mac(_) | Literal::Bytes(_)),
        // A list is compared element-wise, so any element-compatible literal
        // may appear against it.
        FieldKind::List => true,
    }
}

/// Whether a single field value satisfies `value <operator> literal`.
///
/// Values whose type cannot be compared with the literal simply do not match;
/// the compile-time compatibility check is what reports genuine mistakes.
pub(super) fn matches(value: &FieldValue, operator: CompareOperator, literal: &Literal) -> bool {
    if let Some(contained) = containment(value, literal) {
        // Prefix literals describe a set, so only membership is meaningful.
        return match operator {
            CompareOperator::Equal => contained,
            CompareOperator::NotEqual => !contained,
            _ => false,
        };
    }
    // A list matches when any element does, mirroring how repeated layers and
    // multi-field paths behave elsewhere in the grammar.
    if let FieldValue::List(values) = value {
        return values
            .iter()
            .any(|element| matches(element, operator, literal));
    }
    let Some(ordering) = compare(value, literal) else {
        return false;
    };
    match operator {
        CompareOperator::Equal => ordering == Ordering::Equal,
        CompareOperator::NotEqual => ordering != Ordering::Equal,
        CompareOperator::Greater => ordering == Ordering::Greater,
        CompareOperator::GreaterOrEqual => ordering != Ordering::Less,
        CompareOperator::Less => ordering == Ordering::Less,
        CompareOperator::LessOrEqual => ordering != Ordering::Greater,
    }
}

/// Tests prefix membership, or reports [`None`] when the literal is not a prefix.
fn containment(value: &FieldValue, literal: &Literal) -> Option<bool> {
    match (value, literal) {
        (FieldValue::Ipv4(address), Literal::Ipv4Net(network, prefix)) => {
            let mask = prefix_mask_u32(*prefix);
            Some(u32::from(*address) & mask == u32::from(*network) & mask)
        }
        (FieldValue::Ipv6(address), Literal::Ipv6Net(network, prefix)) => {
            let mask = prefix_mask_u128(*prefix);
            Some(u128::from(*address) & mask == u128::from(*network) & mask)
        }
        _ => None,
    }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (u32::BITS - u32::from(prefix))
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (u128::BITS - u32::from(prefix))
    }
}

/// Orders a field value against a literal of a comparable type.
fn compare(value: &FieldValue, literal: &Literal) -> Option<Ordering> {
    match (value, literal) {
        (FieldValue::Bool(left), Literal::Bool(right)) => Some(left.cmp(right)),
        (FieldValue::Bool(left), Literal::Unsigned(right)) => Some(u64::from(*left).cmp(right)),
        (FieldValue::Unsigned(left), Literal::Unsigned(right)) => Some(left.cmp(right)),
        (FieldValue::Unsigned(left), Literal::Signed(right)) => {
            Some(i128::from(*left).cmp(&i128::from(*right)))
        }
        (FieldValue::Signed(left), Literal::Signed(right)) => Some(left.cmp(right)),
        (FieldValue::Signed(left), Literal::Unsigned(right)) => {
            Some(i128::from(*left).cmp(&i128::from(*right)))
        }
        (FieldValue::Text(left), Literal::Text(right)) => Some(left.as_str().cmp(right.as_str())),
        (FieldValue::Bytes(left), Literal::Bytes(right)) => Some(left.as_ref().cmp(right.as_ref())),
        (FieldValue::Bytes(left), Literal::Mac(right)) => Some(left.as_ref().cmp(right.as_slice())),
        (FieldValue::Bytes(left), Literal::Text(right)) => {
            Some(left.as_ref().cmp(right.as_bytes()))
        }
        // A one-byte field compares against a plain number, so a single byte
        // can be written without an ambiguous bare hex pair.
        (FieldValue::Bytes(left), Literal::Unsigned(right)) => match left.as_ref() {
            [only] => Some(u64::from(*only).cmp(right)),
            _ => None,
        },
        (FieldValue::Mac(left), Literal::Mac(right)) => Some(left.cmp(right)),
        (FieldValue::Mac(left), Literal::Bytes(right)) => Some(left.as_slice().cmp(right.as_ref())),
        (FieldValue::Ipv4(left), Literal::Ipv4(right)) => Some(left.cmp(right)),
        (FieldValue::Ipv6(left), Literal::Ipv6(right)) => Some(left.cmp(right)),
        _ => None,
    }
}

/// Whether `contains` can search a field of this kind at all.
///
/// Only the kinds [`contains`] treats as a byte haystack qualify. Slicing a
/// field first narrows it to bytes, so `ipv4.source[0:2] contains 0a:00`
/// still works even though an unsliced address does not.
pub(super) fn searchable(kind: FieldKind) -> bool {
    matches!(kind, FieldKind::Bytes | FieldKind::Text | FieldKind::Mac)
}

/// Whether a literal can serve as a `contains` needle.
pub(super) fn searchable_needle(literal: &Literal) -> bool {
    matches!(
        literal,
        Literal::Bytes(_) | Literal::Text(_) | Literal::Mac(_)
    )
}

/// Whether a field value contains the literal as a subsequence.
pub(super) fn contains(value: &FieldValue, needle: &Literal) -> bool {
    if let FieldValue::List(values) = value {
        return values.iter().any(|element| contains(element, needle));
    }
    let haystack: &[u8] = match value {
        FieldValue::Bytes(bytes) => bytes.as_ref(),
        FieldValue::Text(text) => text.as_bytes(),
        FieldValue::Mac(mac) => mac.as_slice(),
        _ => return false,
    };
    let needle: &[u8] = match needle {
        Literal::Bytes(bytes) => bytes.as_ref(),
        Literal::Text(text) => text.as_bytes(),
        Literal::Mac(mac) => mac.as_slice(),
        _ => return false,
    };
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use super::*;

    #[test]
    fn literal_parser_recognizes_every_supported_shape() {
        assert_eq!(parse("true"), Some(Literal::Bool(true)));
        assert_eq!(parse("false"), Some(Literal::Bool(false)));
        assert_eq!(parse("0xFF"), Some(Literal::Unsigned(255)));
        assert_eq!(parse("42"), Some(Literal::Unsigned(42)));
        assert_eq!(parse("-42"), Some(Literal::Signed(-42)));
        assert_eq!(
            parse("192.0.2.1"),
            Some(Literal::Ipv4("192.0.2.1".parse().unwrap()))
        );
        assert_eq!(
            parse("2001:db8::1"),
            Some(Literal::Ipv6("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(
            parse("192.0.2.0/24"),
            Some(Literal::Ipv4Net("192.0.2.0".parse().unwrap(), 24))
        );
        assert_eq!(
            parse("2001:db8::/32"),
            Some(Literal::Ipv6Net("2001:db8::".parse().unwrap(), 32))
        );
        assert_eq!(
            parse("00:01:0a:10:fe:ff"),
            Some(Literal::Mac([0, 1, 10, 16, 254, 255]))
        );
        assert_eq!(
            parse("de-ad-be-ef"),
            Some(Literal::Bytes(Bytes::from_static(&[
                0xde, 0xad, 0xbe, 0xef
            ])))
        );
    }

    #[test]
    fn literal_parser_rejects_malformed_and_out_of_range_shapes() {
        for input in [
            "",
            "0x",
            "0x10000000000000000",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.0/nope",
            "aa:bb-cc",
            "a:bb",
            "gg:00",
            "aa",
        ] {
            assert_eq!(parse(input), None, "{input}");
        }
    }

    #[test]
    fn literal_display_is_stable_for_every_variant() {
        let cases = [
            (Literal::Bool(true), "true"),
            (Literal::Unsigned(7), "7"),
            (Literal::Signed(-7), "-7"),
            (Literal::Text("text".to_owned()), "\"text\""),
            (
                Literal::Bytes(Bytes::from_static(&[0, 10, 255])),
                "00:0a:ff",
            ),
            (Literal::Ipv4(Ipv4Addr::LOCALHOST), "127.0.0.1"),
            (Literal::Ipv6(Ipv6Addr::LOCALHOST), "::1"),
            (Literal::Ipv4Net(Ipv4Addr::UNSPECIFIED, 0), "0.0.0.0/0"),
            (Literal::Ipv6Net(Ipv6Addr::UNSPECIFIED, 0), "::/0"),
            (Literal::Mac([0, 1, 10, 16, 254, 255]), "00:01:0a:10:fe:ff"),
        ];
        for (literal, expected) in cases {
            assert_eq!(literal.to_string(), expected);
        }
    }

    #[test]
    fn prefix_and_kind_metadata_are_exhaustive() {
        assert!(Literal::Ipv4Net(Ipv4Addr::UNSPECIFIED, 0).is_prefix());
        assert!(Literal::Ipv6Net(Ipv6Addr::UNSPECIFIED, 0).is_prefix());
        assert!(!Literal::Ipv4(Ipv4Addr::UNSPECIFIED).is_prefix());
        let names = [
            (FieldKind::Bool, "a boolean"),
            (FieldKind::Unsigned, "an unsigned number"),
            (FieldKind::Signed, "a signed number"),
            (FieldKind::Text, "text"),
            (FieldKind::Bytes, "bytes"),
            (FieldKind::Ipv4, "an IPv4 address"),
            (FieldKind::Ipv6, "an IPv6 address"),
            (FieldKind::Mac, "a MAC address"),
            (FieldKind::List, "a list"),
        ];
        for (kind, expected) in names {
            assert_eq!(kind_name(kind), expected);
        }
    }

    #[test]
    fn literal_compatibility_checks_every_field_kind_and_derived_auto() {
        let spec = |kind, derived| FieldSpec { kind, derived };
        assert!(compatible(
            spec(FieldKind::Bool, false),
            &Literal::Bool(true)
        ));
        assert!(compatible(
            spec(FieldKind::Bool, false),
            &Literal::Unsigned(1)
        ));
        assert!(!compatible(
            spec(FieldKind::Bool, false),
            &Literal::Unsigned(2)
        ));
        assert!(compatible(
            spec(FieldKind::Unsigned, false),
            &Literal::Signed(-1)
        ));
        assert!(compatible(
            spec(FieldKind::Signed, true),
            &Literal::Text("auto".to_owned())
        ));
        assert!(!compatible(
            spec(FieldKind::Signed, false),
            &Literal::Text("auto".to_owned())
        ));
        assert!(compatible(
            spec(FieldKind::Text, false),
            &Literal::Text("text".to_owned())
        ));
        assert!(compatible(
            spec(FieldKind::Bytes, false),
            &Literal::Unsigned(255)
        ));
        assert!(!compatible(
            spec(FieldKind::Bytes, false),
            &Literal::Unsigned(256)
        ));
        assert!(compatible(
            spec(FieldKind::Ipv4, false),
            &Literal::Ipv4Net(Ipv4Addr::UNSPECIFIED, 0)
        ));
        assert!(compatible(
            spec(FieldKind::Ipv6, false),
            &Literal::Ipv6(Ipv6Addr::LOCALHOST)
        ));
        assert!(compatible(
            spec(FieldKind::Mac, false),
            &Literal::Bytes(Bytes::new())
        ));
        assert!(compatible(
            spec(FieldKind::List, false),
            &Literal::Bool(true)
        ));
    }

    #[test]
    fn comparison_supports_ordering_lists_prefixes_and_incompatible_values() {
        assert!(matches(
            &FieldValue::Unsigned(2),
            CompareOperator::Greater,
            &Literal::Signed(1)
        ));
        assert!(matches(
            &FieldValue::Signed(-1),
            CompareOperator::Less,
            &Literal::Unsigned(0)
        ));
        assert!(matches(
            &FieldValue::Bool(true),
            CompareOperator::Equal,
            &Literal::Unsigned(1)
        ));
        assert!(matches(
            &FieldValue::Ipv4("192.0.2.5".parse().unwrap()),
            CompareOperator::Equal,
            &Literal::Ipv4Net("192.0.2.0".parse().unwrap(), 24)
        ));
        assert!(matches(
            &FieldValue::Ipv6("2001:db8::5".parse().unwrap()),
            CompareOperator::NotEqual,
            &Literal::Ipv6Net("2001:db9::".parse().unwrap(), 32)
        ));
        assert!(!matches(
            &FieldValue::Ipv4(Ipv4Addr::LOCALHOST),
            CompareOperator::Greater,
            &Literal::Ipv4Net(Ipv4Addr::UNSPECIFIED, 0)
        ));
        assert!(matches(
            &FieldValue::List(vec![FieldValue::Unsigned(1), FieldValue::Unsigned(2),]),
            CompareOperator::GreaterOrEqual,
            &Literal::Unsigned(2)
        ));
        assert!(!matches(
            &FieldValue::Text("text".to_owned()),
            CompareOperator::Equal,
            &Literal::Bool(true)
        ));
    }

    #[test]
    fn byte_comparison_covers_bytes_text_mac_and_single_byte_numbers() {
        assert!(matches(
            &FieldValue::Bytes(Bytes::from_static(b"abc")),
            CompareOperator::Equal,
            &Literal::Text("abc".to_owned())
        ));
        assert!(matches(
            &FieldValue::Bytes(Bytes::from_static(&[1])),
            CompareOperator::Equal,
            &Literal::Unsigned(1)
        ));
        assert!(!matches(
            &FieldValue::Bytes(Bytes::from_static(&[1, 2])),
            CompareOperator::Equal,
            &Literal::Unsigned(1)
        ));
        assert!(matches(
            &FieldValue::Mac([0, 1, 2, 3, 4, 5]),
            CompareOperator::Equal,
            &Literal::Bytes(Bytes::from_static(&[0, 1, 2, 3, 4, 5]))
        ));
    }

    #[test]
    fn contains_supports_all_searchable_kinds_lists_and_empty_needles() {
        assert!(searchable(FieldKind::Bytes));
        assert!(searchable(FieldKind::Text));
        assert!(searchable(FieldKind::Mac));
        assert!(!searchable(FieldKind::Unsigned));
        assert!(searchable_needle(&Literal::Bytes(Bytes::new())));
        assert!(searchable_needle(&Literal::Text(String::new())));
        assert!(searchable_needle(&Literal::Mac([0; 6])));
        assert!(!searchable_needle(&Literal::Unsigned(0)));

        assert!(contains(
            &FieldValue::Bytes(Bytes::from_static(b"abcdef")),
            &Literal::Bytes(Bytes::from_static(b"cde"))
        ));
        assert!(contains(
            &FieldValue::Text("abcdef".to_owned()),
            &Literal::Text("".to_owned())
        ));
        assert!(contains(
            &FieldValue::Mac([0, 1, 2, 3, 4, 5]),
            &Literal::Bytes(Bytes::from_static(&[2, 3]))
        ));
        assert!(contains(
            &FieldValue::List(vec![
                FieldValue::Text("first".to_owned()),
                FieldValue::Text("second".to_owned()),
            ]),
            &Literal::Text("cond".to_owned())
        ));
        assert!(!contains(
            &FieldValue::Unsigned(1),
            &Literal::Text("1".to_owned())
        ));
        assert!(!contains(
            &FieldValue::Text("text".to_owned()),
            &Literal::Unsigned(1)
        ));
    }
}
