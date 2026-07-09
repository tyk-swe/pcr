// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

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

    /// Resets a dependent field so the next build derives it again.
    pub fn normalize(&mut self) {
        *self = Self::Auto;
    }
}

/// Stable reflective field types exposed by [`crate::LayerSchema`].
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
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
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

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value),
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
