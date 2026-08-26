// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};

use crate::field::FieldKind;

pub const PACKET_DOCUMENT_SCHEMA_V2: &str = "packetcraftr.packet/v2";

/// A parsed or emitted `packetcraftr.packet/v2` document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    pub layers: Vec<Layer>,
}

/// One protocol layer in a v2 packet document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    pub protocol: String,
    pub fields: Vec<(String, Value)>,
}

/// A dynamically typed field value in a v2 document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Untyped source text from lexical parsing.
    Scalar(String),
    /// Typed scalar carrying its schema kind for numeric/bool serialization.
    ScalarTyped { text: String, kind: FieldKind },
    /// Array of element-kind scalar strings.
    List(Vec<String>),
    /// Derived wire value set to `auto`.
    Auto,
    /// Exact verbatim bytes override on a derived field or raw layer.
    Raw(Bytes),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Scalar(text) | Self::ScalarTyped { text, .. } => Some(text.as_str()),
            Self::Auto => Some("auto"),
            Self::List(_) | Self::Raw(_) => None,
        }
    }
}

/// Formats a stable canonical field path `proto#N.field` for error reporting and diagnostics.
pub fn field_path(layers: &[Layer], index: usize, field: &str) -> String {
    let Some(target_layer) = layers.get(index) else {
        if field.is_empty() {
            return String::new();
        }
        return field.to_owned();
    };

    let mut count = 0_usize;
    for (i, layer) in layers.iter().enumerate() {
        if layer.protocol == target_layer.protocol {
            count = count.saturating_add(1);
        }
        if i == index {
            break;
        }
    }

    let layer_name = if count <= 1 {
        target_layer.protocol.clone()
    } else {
        format!("{}#{}", target_layer.protocol, count)
    };

    if field.is_empty() {
        layer_name
    } else {
        format!("{layer_name}.{field}")
    }
}

impl Serialize for Document {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("schema", PACKET_DOCUMENT_SCHEMA_V2)?;
        map.serialize_entry("layers", &self.layers)?;
        map.end()
    }
}

impl Serialize for Layer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_key(&self.protocol)?;
        map.serialize_value(&FieldsMap(&self.fields))?;
        map.end()
    }
}

struct FieldsMap<'a>(&'a [(String, Value)]);

impl Serialize for FieldsMap<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::Raw(bytes) => {
                let mut map = serializer.serialize_map(Some(1))?;
                let mut hex =
                    String::with_capacity(bytes.len().saturating_mul(2).saturating_add(2));
                hex.push_str("0x");
                for byte in bytes {
                    use std::fmt::Write as _;
                    let _ = write!(hex, "{byte:02x}");
                }
                map.serialize_entry("raw", &hex)?;
                map.end()
            }
            Self::List(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Self::Scalar(text) => serializer.serialize_str(text),
            Self::ScalarTyped { text, kind } => match kind {
                FieldKind::Bool => {
                    if text.eq_ignore_ascii_case("true") {
                        serializer.serialize_bool(true)
                    } else if text.eq_ignore_ascii_case("false") {
                        serializer.serialize_bool(false)
                    } else {
                        serializer.serialize_str(text)
                    }
                }
                FieldKind::Unsigned => {
                    if let Ok(num) = text.parse::<u64>() {
                        serializer.serialize_u64(num)
                    } else {
                        serializer.serialize_str(text)
                    }
                }
                FieldKind::Signed => {
                    if let Ok(num) = text.parse::<i64>() {
                        serializer.serialize_i64(num)
                    } else {
                        serializer.serialize_str(text)
                    }
                }
                _ => serializer.serialize_str(text),
            },
        }
    }
}
