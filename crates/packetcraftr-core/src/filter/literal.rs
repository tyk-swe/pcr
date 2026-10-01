// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::path::FieldSpec;
use crate::field::FieldKind;

const AUTO_WIRE_VALUE: &str = "auto";

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
    /// An inclusive `low..high` range. Comparing with `==` tests membership.
    Range(Range),
}

/// Both endpoints are the same kind and `low <= high`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Range {
    Unsigned(u64, u64),
    Ipv4(Ipv4Addr, Ipv4Addr),
    Ipv6(Ipv6Addr, Ipv6Addr),
}

impl fmt::Display for Range {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(low, high) => write!(formatter, "{low}..{high}"),
            Self::Ipv4(low, high) => write!(formatter, "{low}..{high}"),
            Self::Ipv6(low, high) => write!(formatter, "{low}..{high}"),
        }
    }
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
            Self::Range(value) => write!(formatter, "{value}"),
        }
    }
}

/// Reads `low..high` when at least one side is a number or an address, so a word such as `a..b` stays text.
///
/// The faults name why a range-shaped word is refused; nothing is partially accepted.
pub(super) fn parse_range(word: &str) -> Option<Result<Literal, &'static str>> {
    let (low, high) = word.split_once("..")?;
    let low = parse(low);
    let high = parse(high);
    let endpoint = |literal: &Option<Literal>| {
        matches!(
            literal,
            Some(Literal::Unsigned(_) | Literal::Signed(_) | Literal::Ipv4(_) | Literal::Ipv6(_))
        )
    };
    if !endpoint(&low) && !endpoint(&high) {
        return None;
    }
    Some(range_between(low, high))
}

fn range_between(low: Option<Literal>, high: Option<Literal>) -> Result<Literal, &'static str> {
    let (Some(low), Some(high)) = (low, high) else {
        return Err("a range needs a number or address at both ends");
    };
    let range = match (low, high) {
        (Literal::Unsigned(low), Literal::Unsigned(high)) => (low <= high)
            .then_some(Range::Unsigned(low, high))
            .ok_or(REVERSED_RANGE)?,
        (Literal::Ipv4(low), Literal::Ipv4(high)) => (low <= high)
            .then_some(Range::Ipv4(low, high))
            .ok_or(REVERSED_RANGE)?,
        (Literal::Ipv6(low), Literal::Ipv6(high)) => (low <= high)
            .then_some(Range::Ipv6(low, high))
            .ok_or(REVERSED_RANGE)?,
        (
            Literal::Unsigned(_) | Literal::Ipv4(_) | Literal::Ipv6(_),
            Literal::Unsigned(_) | Literal::Ipv4(_) | Literal::Ipv6(_),
        ) => return Err("range ends must be the same kind of value"),
        _ => return Err("range ends must be unsigned numbers or IP addresses"),
    };
    Ok(Literal::Range(range))
}

const REVERSED_RANGE: &str = "the start of a range is above its end";

/// Two-digit hex groups form a byte run even at eight groups, where they could also spell an IPv6 address.
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
    if let Some(groups) = hex_groups(word) {
        return match <[u8; 6]>::try_from(groups.as_slice()) {
            Ok(mac) => Some(Literal::Mac(mac)),
            Err(_) => Some(Literal::Bytes(Bytes::from(groups))),
        };
    }
    if let Ok(value) = word.parse::<Ipv6Addr>() {
        return Some(Literal::Ipv6(value));
    }
    if let Ok(value) = word.parse::<u64>() {
        return Some(Literal::Unsigned(value));
    }
    if let Ok(value) = word.parse::<i64>() {
        return Some(Literal::Signed(value));
    }
    None
}

/// Hex digits that `parse` refused as bytes and that would otherwise fall back to ASCII text: bare digits (`c000`) or one- and two-digit groups around a separator (`c0:0`, `47:45:`).
pub(super) fn is_malformed_byte_word(word: &str) -> bool {
    let hex = |text: &str| text.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !word.contains([':', '-']) {
        return word.len() >= 2 && hex(word);
    }
    word.bytes().any(|byte| byte.is_ascii_hexdigit())
        && word
            .split([':', '-'])
            .all(|group| group.len() <= 2 && hex(group))
}

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
    pub(super) fn is_prefix(&self) -> bool {
        matches!(self, Self::Ipv4Net(..) | Self::Ipv6Net(..))
    }

    pub(super) fn is_range(&self) -> bool {
        matches!(self, Self::Range(_))
    }
}

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
        FieldKind::Object => "an object",
    }
}

pub(super) fn compatible(spec: FieldSpec, literal: &Literal) -> bool {
    match spec.kind {
        FieldKind::Bool => matches!(literal, Literal::Bool(_) | Literal::Unsigned(0 | 1)),
        FieldKind::Unsigned | FieldKind::Signed => match literal {
            Literal::Unsigned(_) | Literal::Signed(_) | Literal::Range(Range::Unsigned(..)) => true,
            Literal::Text(text) => spec.derived && text == AUTO_WIRE_VALUE,
            _ => false,
        },
        FieldKind::Text => matches!(literal, Literal::Text(_)),
        FieldKind::Bytes => match literal {
            Literal::Bytes(_) | Literal::Mac(_) | Literal::Text(_) => true,
            Literal::Unsigned(value) => *value <= u64::from(u8::MAX),
            _ => false,
        },
        FieldKind::Ipv4 => matches!(
            literal,
            Literal::Ipv4(_) | Literal::Ipv4Net(..) | Literal::Range(Range::Ipv4(..))
        ),
        FieldKind::Ipv6 => matches!(
            literal,
            Literal::Ipv6(_) | Literal::Ipv6Net(..) | Literal::Range(Range::Ipv6(..))
        ),
        FieldKind::Mac => matches!(literal, Literal::Mac(_) | Literal::Bytes(_)),
        FieldKind::List => true,
        FieldKind::Object => false,
    }
}

/// A list qualifies because the search applies to each element, as in `dns.qname`.
///
/// The schema does not record a scalar list's element kind, so a list of numbers or addresses compiles
/// and never matches. Only lists of objects, which no search can match, are refused.
pub(super) fn searchable(spec: FieldSpec) -> bool {
    match spec.kind {
        FieldKind::Bytes | FieldKind::Text | FieldKind::Mac => true,
        FieldKind::List => !spec.structured,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: FieldKind) -> FieldSpec {
        FieldSpec::synthetic(kind)
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
    fn eight_byte_runs_stay_bytes_while_other_ipv6_spellings_stay_addresses() {
        assert_eq!(
            parse("47:45:54:20:2f:69:6e:64"),
            Some(Literal::Bytes(Bytes::from_static(b"GET /ind")))
        );
        for address in [
            "::1",
            "fe:80::1",
            "1:2:3:4:5:6:7:8",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            "::ffff:192.0.2.1",
        ] {
            assert!(
                matches!(parse(address), Some(Literal::Ipv6(_))),
                "{address}"
            );
        }
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
    fn only_hex_digit_words_that_fail_as_bytes_look_like_mistyped_bytes() {
        for word in [
            "ff", "160301ff", "DEADBEEF", "c000", "123", "47:45:5", "47:45:", ":45", "c0:0",
            "aa:bb-cc", "1-2",
        ] {
            assert!(is_malformed_byte_word(word), "{word}");
        }
        for word in [
            "",
            "f",
            "GET",
            "0xff",
            "auto",
            "fg",
            "dead-beef",
            "2026-09-29",
            "host:80",
            "-",
            "--",
            "::",
        ] {
            assert!(!is_malformed_byte_word(word), "{word}");
        }
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
                derived: true,
                ..spec(FieldKind::Unsigned)
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
    fn range_words_split_on_the_first_pair_of_dots_into_same_kind_ends() {
        assert_eq!(
            parse_range("1024..65535"),
            Some(Ok(Literal::Range(Range::Unsigned(1024, 65535))))
        );
        assert_eq!(
            parse_range("0x10..0x20"),
            Some(Ok(Literal::Range(Range::Unsigned(16, 32))))
        );
        assert_eq!(
            parse_range("5..5"),
            Some(Ok(Literal::Range(Range::Unsigned(5, 5))))
        );
        assert_eq!(
            parse_range("10.0.0.10..10.0.0.50"),
            Some(Ok(Literal::Range(Range::Ipv4(
                Ipv4Addr::new(10, 0, 0, 10),
                Ipv4Addr::new(10, 0, 0, 50)
            ))))
        );
        assert!(matches!(
            parse_range("2001:db8::1..2001:db8::ff"),
            Some(Ok(Literal::Range(Range::Ipv6(..))))
        ));
        assert_eq!(
            Literal::Range(Range::Unsigned(1, 2)).to_string(),
            "1..2".to_owned()
        );
    }

    #[test]
    fn malformed_ranges_are_refused_and_non_numeric_words_are_not_ranges() {
        for malformed in [
            "200..100",
            "1..",
            "..9",
            "1...5",
            "-5..5",
            "1..a",
            "10.0.0.1..::1",
            "10.0.0.1..5",
            "10.0.0.50..10.0.0.10",
            "1..aa:bb",
            "10.0.0.0/8..10.0.0.9",
        ] {
            assert!(
                matches!(parse_range(malformed), Some(Err(_))),
                "{malformed}"
            );
        }
        for text in ["a..b", "..", "plain", "a.b", "www..example", "true..false"] {
            assert_eq!(parse_range(text), None, "{text}");
        }
    }

    #[test]
    fn range_literals_fit_only_fields_of_their_own_kind() {
        let unsigned = Literal::Range(Range::Unsigned(1, 2));
        let v4 = Literal::Range(Range::Ipv4(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST));
        let v6 = Literal::Range(Range::Ipv6(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST));
        assert!(compatible(spec(FieldKind::Unsigned), &unsigned));
        assert!(compatible(spec(FieldKind::Signed), &unsigned));
        assert!(compatible(spec(FieldKind::Ipv4), &v4));
        assert!(compatible(spec(FieldKind::Ipv6), &v6));
        assert!(!compatible(spec(FieldKind::Ipv6), &v4));
        assert!(!compatible(spec(FieldKind::Ipv4), &v6));
        assert!(!compatible(spec(FieldKind::Ipv4), &unsigned));
        assert!(!compatible(spec(FieldKind::Bytes), &unsigned));
        assert!(!compatible(spec(FieldKind::Text), &unsigned));
        assert!(unsigned.is_range());
        assert!(!Literal::Unsigned(1).is_range());
    }

    #[test]
    fn searchable_types_and_prefix_markers_match_evaluation_contracts() {
        for kind in [
            FieldKind::Bytes,
            FieldKind::Text,
            FieldKind::Mac,
            FieldKind::List,
        ] {
            assert!(searchable(spec(kind)), "{}", kind_name(kind));
        }
        let objects = FieldSpec {
            structured: true,
            ..spec(FieldKind::List)
        };
        assert!(!searchable(objects));
        for kind in [
            FieldKind::Bool,
            FieldKind::Unsigned,
            FieldKind::Signed,
            FieldKind::Ipv4,
            FieldKind::Ipv6,
            FieldKind::Object,
        ] {
            assert!(!searchable(spec(kind)), "{}", kind_name(kind));
        }
        assert!(Literal::Ipv4Net(Ipv4Addr::UNSPECIFIED, 0).is_prefix());
        assert!(!Literal::Ipv4(Ipv4Addr::UNSPECIFIED).is_prefix());
    }
}
