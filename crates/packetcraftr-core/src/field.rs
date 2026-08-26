// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Reflective field kinds and values.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CoerceError {
    #[error("expected {expected}, got `{got}`")]
    ValueForm { expected: &'static str, got: String },
    #[error("{got} is above the maximum {max}")]
    OutOfRange { got: String, max: u64 },
    #[error("`auto` is only valid on a derived field")]
    AutoNotDerived,
}

/// Parses one v2 text form by declared kind. `element` is the list element kind; `max` bounds Unsigned values; `derived` allows the bare word `auto`.
pub fn coerce_kind(
    kind: FieldKind,
    _element: Option<FieldKind>,
    max: Option<u64>,
    derived: bool,
    text: &str,
) -> Result<FieldValue, CoerceError> {
    if kind == FieldKind::Text {
        return Ok(FieldValue::Text(text.to_owned()));
    }
    if text.eq_ignore_ascii_case("auto") {
        if derived {
            return Ok(FieldValue::Text("auto".to_owned()));
        }
        return Err(CoerceError::AutoNotDerived);
    }
    match kind {
        FieldKind::Bool => {
            if text.eq_ignore_ascii_case("true") {
                Ok(FieldValue::Bool(true))
            } else if text.eq_ignore_ascii_case("false") {
                Ok(FieldValue::Bool(false))
            } else {
                Err(CoerceError::ValueForm {
                    expected: "a boolean (true/false)",
                    got: text.to_owned(),
                })
            }
        }
        FieldKind::Unsigned => {
            if text.is_empty()
                || text.starts_with('+')
                || text.starts_with('-')
                || text.contains('_')
            {
                return Err(CoerceError::ValueForm {
                    expected: "an unsigned integer (decimal or 0x hex)",
                    got: text.to_owned(),
                });
            }
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(CoerceError::ValueForm {
                        expected: "an unsigned integer (decimal or 0x hex)",
                        got: text.to_owned(),
                    });
                }
                match u64::from_str_radix(hex, 16) {
                    Ok(val) => {
                        if let Some(limit) = max
                            && val > limit
                        {
                            return Err(CoerceError::OutOfRange {
                                got: text.to_owned(),
                                max: limit,
                            });
                        }
                        Ok(FieldValue::Unsigned(val))
                    }
                    Err(_) => Err(CoerceError::ValueForm {
                        expected: "an unsigned integer (decimal or 0x hex)",
                        got: text.to_owned(),
                    }),
                }
            } else {
                if !text.chars().all(|c| c.is_ascii_digit()) {
                    return Err(CoerceError::ValueForm {
                        expected: "an unsigned integer (decimal or 0x hex)",
                        got: text.to_owned(),
                    });
                }
                match text.parse::<u64>() {
                    Ok(val) => {
                        if let Some(limit) = max
                            && val > limit
                        {
                            return Err(CoerceError::OutOfRange {
                                got: text.to_owned(),
                                max: limit,
                            });
                        }
                        Ok(FieldValue::Unsigned(val))
                    }
                    Err(_) => Err(CoerceError::ValueForm {
                        expected: "an unsigned integer (decimal or 0x hex)",
                        got: text.to_owned(),
                    }),
                }
            }
        }
        FieldKind::Signed => {
            if text.is_empty() || text.starts_with('+') || text.contains('_') {
                return Err(CoerceError::ValueForm {
                    expected: "a signed integer (decimal or 0x hex)",
                    got: text.to_owned(),
                });
            }
            let (neg, rest) = if let Some(stripped) = text.strip_prefix('-') {
                (true, stripped)
            } else {
                (false, text)
            };
            if rest.is_empty() {
                return Err(CoerceError::ValueForm {
                    expected: "a signed integer (decimal or 0x hex)",
                    got: text.to_owned(),
                });
            }
            if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
                if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(CoerceError::ValueForm {
                        expected: "a signed integer (decimal or 0x hex)",
                        got: text.to_owned(),
                    });
                }
                match u64::from_str_radix(hex, 16) {
                    Ok(val) => {
                        if neg {
                            if val == 1_u64 << 63 {
                                Ok(FieldValue::Signed(i64::MIN))
                            } else {
                                let pos =
                                    i64::try_from(val).map_err(|_| CoerceError::ValueForm {
                                        expected: "a signed integer (decimal or 0x hex)",
                                        got: text.to_owned(),
                                    })?;
                                let signed =
                                    pos.checked_neg().ok_or_else(|| CoerceError::ValueForm {
                                        expected: "a signed integer (decimal or 0x hex)",
                                        got: text.to_owned(),
                                    })?;
                                Ok(FieldValue::Signed(signed))
                            }
                        } else {
                            let signed =
                                i64::try_from(val).map_err(|_| CoerceError::ValueForm {
                                    expected: "a signed integer (decimal or 0x hex)",
                                    got: text.to_owned(),
                                })?;
                            Ok(FieldValue::Signed(signed))
                        }
                    }
                    Err(_) => Err(CoerceError::ValueForm {
                        expected: "a signed integer (decimal or 0x hex)",
                        got: text.to_owned(),
                    }),
                }
            } else {
                if !rest.chars().all(|c| c.is_ascii_digit()) {
                    return Err(CoerceError::ValueForm {
                        expected: "a signed integer (decimal or 0x hex)",
                        got: text.to_owned(),
                    });
                }
                match text.parse::<i64>() {
                    Ok(val) => Ok(FieldValue::Signed(val)),
                    Err(_) => Err(CoerceError::ValueForm {
                        expected: "a signed integer (decimal or 0x hex)",
                        got: text.to_owned(),
                    }),
                }
            }
        }
        FieldKind::Text => Ok(FieldValue::Text(text.to_owned())),
        FieldKind::Bytes => {
            let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) else {
                return Err(CoerceError::ValueForm {
                    expected: "bytes as 0x followed by an even number of hex digits",
                    got: text.to_owned(),
                });
            };
            if hex.is_empty() {
                return Ok(FieldValue::Bytes(Bytes::new()));
            }
            if hex.len() % 2 != 0 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CoerceError::ValueForm {
                    expected: "bytes as 0x followed by an even number of hex digits",
                    got: text.to_owned(),
                });
            }
            let hex_bytes = hex.as_bytes();
            let mut out = Vec::with_capacity(hex_bytes.len() / 2);
            for chunk in hex_bytes.chunks_exact(2) {
                if let (Some(&high), Some(&low)) = (chunk.first(), chunk.get(1)) {
                    let h = hex_nibble(high).ok_or_else(|| CoerceError::ValueForm {
                        expected: "bytes as 0x followed by an even number of hex digits",
                        got: text.to_owned(),
                    })?;
                    let l = hex_nibble(low).ok_or_else(|| CoerceError::ValueForm {
                        expected: "bytes as 0x followed by an even number of hex digits",
                        got: text.to_owned(),
                    })?;
                    out.push((h << 4) | l);
                }
            }
            Ok(FieldValue::Bytes(Bytes::from(out)))
        }
        FieldKind::Ipv4 => match Ipv4Addr::from_str(text) {
            Ok(addr) => Ok(FieldValue::Ipv4(addr)),
            Err(_) => Err(CoerceError::ValueForm {
                expected: "an IPv4 address",
                got: text.to_owned(),
            }),
        },
        FieldKind::Ipv6 => {
            if text.contains('%') {
                return Err(CoerceError::ValueForm {
                    expected: "an IPv6 address",
                    got: text.to_owned(),
                });
            }
            match Ipv6Addr::from_str(text) {
                Ok(addr) => Ok(FieldValue::Ipv6(addr)),
                Err(_) => Err(CoerceError::ValueForm {
                    expected: "an IPv6 address",
                    got: text.to_owned(),
                }),
            }
        }
        FieldKind::Mac => match parse_mac(text) {
            Some(mac) => Ok(FieldValue::Mac(mac)),
            None => Err(CoerceError::ValueForm {
                expected: "a MAC address",
                got: text.to_owned(),
            }),
        },
        FieldKind::List => Err(CoerceError::ValueForm {
            expected: "list",
            got: text.to_owned(),
        }),
    }
}

#[expect(
    clippy::arithmetic_side_effects,
    reason = "each arm bounds value to its own ASCII range, so subtraction and addition stay inside u8"
)]
fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Schema-driven wrapper. This branch passes `element: None`, `max: None`, `derived: schema.derived`; the reflection branch fills in the new schema slots after merge.
pub fn coerce(schema: &crate::layer::FieldSchema, text: &str) -> Result<FieldValue, CoerceError> {
    coerce_kind(schema.kind, None, None, schema.derived, text)
}

/// A value whose wire representation may be derived, exact, or deliberately raw.
///
/// Fresh protocol layers normally use [`WireValue::Auto`] for checksums, lengths,
/// offsets, and discriminators. Decoders use [`WireValue::Exact`] so an untouched
/// decoded packet can be rebuilt byte-for-byte.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "value", rename_all = "snake_case")]
pub enum WireValue<T> {
    /// Derive the value from the final packet and build context.
    #[default]
    Auto,
    /// Emit and validate this exact typed value.
    Exact(T),
    /// Emit these bytes verbatim in permissive mode.
    Raw(Bytes),
}

impl<T> WireValue<T> {
    /// Returns the exact value, if this is [`WireValue::Exact`].
    pub fn exact(&self) -> Option<&T> {
        match self {
            Self::Exact(value) => Some(value),
            Self::Auto | Self::Raw(_) => None,
        }
    }
}

/// Stable reflective field types exposed by [`crate::layer::Schema`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Bool,
    Unsigned,
    Signed,
    Text,
    Bytes,
    Ipv4,
    Ipv6,
    Mac,
    List,
}

/// A dynamically inspectable or editable layer-field value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum FieldValue {
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Text(String),
    Bytes(#[serde(with = "bytes_as_array")] Bytes),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Mac([u8; 6]),
    List(Vec<FieldValue>),
}

pub(crate) fn parse_mac(input: &str) -> Option<[u8; 6]> {
    let mut parts = input.split([':', '-']);
    let mut output = [0_u8; 6];
    for byte in &mut output {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    parts.next().is_none().then_some(output)
}

mod bytes_as_array {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S>(value: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.as_ref().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer).map(Bytes::from)
    }
}

impl FieldValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

impl From<bool> for FieldValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

macro_rules! unsigned_field_value {
    ($($ty:ty),+ $(,)?) => {
        $(impl From<$ty> for FieldValue {
            fn from(value: $ty) -> Self {
                Self::Unsigned(value as u64)
            }
        })+
    };
}

unsigned_field_value!(u8, u16, u32, u64, usize);

impl From<String> for FieldValue {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for FieldValue {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

impl From<Bytes> for FieldValue {
    fn from(value: Bytes) -> Self {
        Self::Bytes(value)
    }
}

impl From<Vec<u8>> for FieldValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Bytes(Bytes::from(value))
    }
}

impl From<Ipv4Addr> for FieldValue {
    fn from(value: Ipv4Addr) -> Self {
        Self::Ipv4(value)
    }
}

impl From<Ipv6Addr> for FieldValue {
    fn from(value: Ipv6Addr) -> Self {
        Self::Ipv6(value)
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(value) => write!(formatter, "{value}"),
            Self::Unsigned(value) => write!(formatter, "{value}"),
            Self::Signed(value) => write!(formatter, "{value}"),
            Self::Text(value) => formatter.write_str(value),
            Self::Bytes(value) => {
                for byte in value {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Ipv4(value) => write!(formatter, "{value}"),
            Self::Ipv6(value) => write!(formatter, "{value}"),
            Self::Mac(value) => write!(
                formatter,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                value[0], value[1], value[2], value[3], value[4], value[5]
            ),
            Self::List(values) => {
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(",")?;
                    }
                    write!(formatter, "{value}")?;
                }
                Ok(())
            }
        }
    }
}
