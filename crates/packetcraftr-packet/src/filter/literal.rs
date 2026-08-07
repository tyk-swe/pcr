// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Filter-literal parsing and compile-time field compatibility.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::super::field::FieldKind;
use super::path::FieldSpec;

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
