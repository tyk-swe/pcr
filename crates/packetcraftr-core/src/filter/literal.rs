// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Filter-literal parsing and compile-time field compatibility.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::path::FieldSpec;
use crate::field::FieldKind;

/// How an unbuilt derived wire value reflects through [`crate::field::FieldValue`].
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
            // Only derived numeric fields accept reflected `auto` text.
            Literal::Text(text) => spec.derived && text == AUTO_WIRE_VALUE,
            _ => false,
        },
        FieldKind::Text => matches!(literal, Literal::Text(_)),
        // Byte fields also accept a one-byte number.
        FieldKind::Bytes => match literal {
            Literal::Bytes(_) | Literal::Mac(_) | Literal::Text(_) => true,
            Literal::Unsigned(value) => *value <= u64::from(u8::MAX),
            _ => false,
        },
        FieldKind::Ipv4 => matches!(literal, Literal::Ipv4(_) | Literal::Ipv4Net(..)),
        FieldKind::Ipv6 => matches!(literal, Literal::Ipv6(_) | Literal::Ipv6Net(..)),
        FieldKind::Mac => matches!(literal, Literal::Mac(_) | Literal::Bytes(_)),
        // Lists compare element-wise.
        FieldKind::List => true,
    }
}

/// Whether `contains` can search a field of this kind at all.
///
/// Only the kinds evaluated as a byte haystack qualify. Slicing a
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

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: FieldKind) -> FieldSpec {
        FieldSpec {
            kind,
            derived: false,
        }
    }

    #[test]
    fn literal_shapes_are_disambiguated_before_broader_hex_and_number_forms() {
        assert_eq!(parse("true"), Some(Literal::Bool(true)));
        assert_eq!(parse("0Xff"), Some(Literal::Unsigned(255)));
        assert_eq!(
            parse("192.0.2.1/24"),
            Some(Literal::Ipv4Net(Ipv4Addr::new(192, 0, 2, 1), 24))
        );
        assert!(matches!(
            parse("2001:db8::1/64"),
            Some(Literal::Ipv6Net(..))
        ));
        assert!(matches!(parse("2001:db8::1"), Some(Literal::Ipv6(..))));
        assert_eq!(
            parse("00:11:22:33:44:55"),
            Some(Literal::Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(
            parse("47:45:54:20"),
            Some(Literal::Bytes(Bytes::from_static(b"GET ")))
        );
        assert_eq!(
            parse("18446744073709551615"),
            Some(Literal::Unsigned(u64::MAX))
        );
        assert_eq!(parse("-42"), Some(Literal::Signed(-42)));
    }

    #[test]
    fn malformed_literal_shapes_are_not_partially_accepted() {
        for malformed in [
            "0x",
            "0xgg",
            "192.0.2.1/33",
            "2001:db8::1/129",
            "aa:bb-cc",
            "a:bb",
            "aa:",
            "ff",
        ] {
            assert_eq!(parse(malformed), None, "{malformed}");
        }
    }

    #[test]
    fn literal_display_is_stable_for_machine_and_human_readable_values() {
        let cases = [
            (Literal::Bool(false), "false"),
            (Literal::Unsigned(7), "7"),
            (Literal::Signed(-7), "-7"),
            (Literal::Text("dns".to_owned()), "\"dns\""),
            (
                Literal::Bytes(Bytes::from_static(&[0, 0xab, 0xff])),
                "00:ab:ff",
            ),
            (Literal::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), "192.0.2.1"),
            (
                Literal::Ipv4Net(Ipv4Addr::new(192, 0, 2, 0), 24),
                "192.0.2.0/24",
            ),
            (Literal::Mac([0, 1, 2, 3, 4, 5]), "00:01:02:03:04:05"),
        ];

        for (literal, expected) in cases {
            assert_eq!(literal.to_string(), expected);
        }
        assert_eq!(
            Literal::Ipv6("2001:db8::1".parse().expect("fixture address")).to_string(),
            "2001:db8::1"
        );
        assert_eq!(
            Literal::Ipv6Net("2001:db8::".parse().expect("fixture prefix"), 32).to_string(),
            "2001:db8::/32"
        );
    }

    #[test]
    fn field_compatibility_rejects_impossible_comparisons() {
        assert!(compatible(spec(FieldKind::Bool), &Literal::Bool(true)));
        assert!(compatible(spec(FieldKind::Bool), &Literal::Unsigned(1)));
        assert!(!compatible(spec(FieldKind::Bool), &Literal::Unsigned(2)));
        assert!(compatible(spec(FieldKind::Signed), &Literal::Unsigned(1)));
        assert!(compatible(spec(FieldKind::Unsigned), &Literal::Signed(-1)));
        assert!(!compatible(
            spec(FieldKind::Unsigned),
            &Literal::Text(AUTO_WIRE_VALUE.to_owned())
        ));
        assert!(compatible(
            FieldSpec {
                kind: FieldKind::Unsigned,
                derived: true,
            },
            &Literal::Text(AUTO_WIRE_VALUE.to_owned())
        ));
        assert!(compatible(spec(FieldKind::Bytes), &Literal::Unsigned(255)));
        assert!(!compatible(spec(FieldKind::Bytes), &Literal::Unsigned(256)));
        assert!(compatible(
            spec(FieldKind::Ipv4),
            &Literal::Ipv4Net(Ipv4Addr::UNSPECIFIED, 0)
        ));
        assert!(compatible(
            spec(FieldKind::Mac),
            &Literal::Bytes(Bytes::from_static(&[0, 1]))
        ));
        assert!(compatible(spec(FieldKind::List), &Literal::Bool(false)));
    }

    #[test]
    fn searchable_types_and_prefix_markers_match_evaluation_contracts() {
        for kind in [FieldKind::Bytes, FieldKind::Text, FieldKind::Mac] {
            assert!(searchable(kind), "{}", kind_name(kind));
        }
        for kind in [
            FieldKind::Bool,
            FieldKind::Unsigned,
            FieldKind::Signed,
            FieldKind::Ipv4,
            FieldKind::Ipv6,
            FieldKind::List,
        ] {
            assert!(!searchable(kind), "{}", kind_name(kind));
        }
        assert!(searchable_needle(&Literal::Text("x".to_owned())));
        assert!(searchable_needle(&Literal::Mac([0; 6])));
        assert!(!searchable_needle(&Literal::Unsigned(0)));
        assert!(Literal::Ipv4Net(Ipv4Addr::UNSPECIFIED, 0).is_prefix());
        assert!(!Literal::Ipv4(Ipv4Addr::UNSPECIFIED).is_prefix());
    }
}
