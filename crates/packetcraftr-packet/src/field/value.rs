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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use super::{FieldValue, WireValue};

    #[test]
    fn wire_value_exact_accepts_only_exact_values() {
        assert_eq!(WireValue::Exact(7_u16).exact(), Some(&7));
        assert_eq!(WireValue::<u16>::Auto.exact(), None);
        assert_eq!(
            WireValue::<u16>::Raw(Bytes::from_static(&[1, 2])).exact(),
            None
        );
    }

    #[test]
    fn field_value_accessors_accept_only_their_declared_kind() {
        assert_eq!(FieldValue::Unsigned(42).as_u64(), Some(42));
        assert_eq!(FieldValue::Bool(true).as_bool(), Some(true));
        assert_eq!(FieldValue::Signed(42).as_u64(), None);
        assert_eq!(FieldValue::Unsigned(1).as_bool(), None);
    }

    #[test]
    fn primitive_conversions_preserve_values() {
        for value in [
            FieldValue::from(1_u8),
            FieldValue::from(1_u16),
            FieldValue::from(1_u32),
            FieldValue::from(1_u64),
            FieldValue::from(1_usize),
        ] {
            assert_eq!(value, FieldValue::Unsigned(1));
        }
        assert_eq!(FieldValue::from(true), FieldValue::Bool(true));
        assert_eq!(
            FieldValue::from("text"),
            FieldValue::Text("text".to_owned())
        );
        assert_eq!(
            FieldValue::from("owned".to_owned()),
            FieldValue::Text("owned".to_owned())
        );
        assert_eq!(
            FieldValue::from(vec![1, 2]),
            FieldValue::Bytes(Bytes::from_static(&[1, 2]))
        );
        assert_eq!(
            FieldValue::from(Bytes::from_static(&[3, 4])),
            FieldValue::Bytes(Bytes::from_static(&[3, 4]))
        );
        assert_eq!(
            FieldValue::from(Ipv4Addr::LOCALHOST),
            FieldValue::Ipv4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            FieldValue::from(Ipv6Addr::LOCALHOST),
            FieldValue::Ipv6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn display_is_stable_for_every_field_value_kind() {
        let cases = [
            (FieldValue::Bool(true), "true"),
            (FieldValue::Unsigned(42), "42"),
            (FieldValue::Signed(-42), "-42"),
            (FieldValue::Text("text".to_owned()), "text"),
            (
                FieldValue::Bytes(Bytes::from_static(&[0, 1, 254, 255])),
                "0001feff",
            ),
            (FieldValue::Ipv4(Ipv4Addr::LOCALHOST), "127.0.0.1"),
            (FieldValue::Ipv6(Ipv6Addr::LOCALHOST), "::1"),
            (
                FieldValue::Mac([0, 1, 10, 16, 254, 255]),
                "00:01:0a:10:fe:ff",
            ),
            (
                FieldValue::List(vec![
                    FieldValue::Unsigned(1),
                    FieldValue::Text("two".to_owned()),
                ]),
                "1,two",
            ),
            (FieldValue::List(Vec::new()), ""),
        ];
        for (value, expected) in cases {
            assert_eq!(value.to_string(), expected);
        }
    }

    #[test]
    fn bytes_serde_uses_a_numeric_array_and_round_trips() {
        let value = FieldValue::Bytes(Bytes::from_static(&[0, 127, 255]));
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(json, r#"{"type":"bytes","value":[0,127,255]}"#);
        assert_eq!(serde_json::from_str::<FieldValue>(&json).unwrap(), value);
    }
}
