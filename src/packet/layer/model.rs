// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::super::field::{FieldKind, FieldValue};
use super::reflection::{reflect_get, reflect_set, reflective_layer};

/// An open, stable identifier for a protocol layer or codec.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolId(String);

impl ProtocolId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ProtocolId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ProtocolId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldSchema {
    /// Stable reflective field name used by documents, expressions, and
    /// [`Layer::field`].
    pub name: &'static str,
    /// Nominal typed value accepted by the field. Derived wire values may also
    /// expose `"auto"` or raw bytes through [`FieldValue`].
    pub kind: FieldKind,
    /// Whether the builder may derive this field from packet context.
    pub derived: bool,
    /// Whether [`Layer::field`] must return a value after codec defaults have
    /// been applied.
    ///
    /// This does not require callers to spell the field in an expression or
    /// document. Codec factories may supply a default, but constructed,
    /// materialized, and decoded layers must expose every required field.
    pub required: bool,
    /// Human-readable field purpose.
    pub description: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LayerSchema {
    /// Stable protocol identifier.
    pub protocol: ProtocolId,
    /// Human-readable protocol name.
    pub name: &'static str,
    /// Ordered reflective fields.
    pub fields: &'static [FieldSchema],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldError {
    #[error("layer {protocol} has no field named {field}")]
    UnknownField { protocol: ProtocolId, field: String },
    #[error("field {field} on layer {protocol} expected {expected}")]
    WrongType {
        protocol: ProtocolId,
        field: String,
        expected: &'static str,
    },
    #[error("field {field} on layer {protocol} is outside the allowed range")]
    OutOfRange { protocol: ProtocolId, field: String },
    #[error("field {field} on layer {protocol} cannot be edited reflectively")]
    ReadOnly { protocol: ProtocolId, field: String },
    #[error("required field {field} is absent from layer {protocol} after defaults")]
    MissingRequired { protocol: ProtocolId, field: String },
}

/// Object-safe packet layer interface used by built-in and external protocols.
pub trait Layer: Any + Send + Sync + fmt::Debug {
    fn schema(&self) -> &'static LayerSchema;
    fn clone_box(&self) -> Box<dyn Layer>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn field(&self, name: &str) -> Option<FieldValue>;
    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError>;

    /// Validates the stable required-field contract after codec defaults,
    /// materialization, or decoding.
    fn validate_required_fields(&self) -> Result<(), FieldError> {
        for field in self.schema().fields.iter().filter(|field| field.required) {
            if self.field(field.name).is_none() {
                return Err(FieldError::MissingRequired {
                    protocol: self.protocol_id(),
                    field: field.name.to_owned(),
                });
            }
        }
        Ok(())
    }

    fn protocol_id(&self) -> ProtocolId {
        self.schema().protocol.clone()
    }

    /// Reset dependent values to automatic derivation.
    fn normalize(&mut self) {}

    #[cfg(test)]
    fn declared_layout_fields(&self) -> Vec<&'static str> {
        Vec::new()
    }
}

impl Clone for Box<dyn Layer> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Raw {
    pub bytes: Bytes,
}

impl Raw {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

reflective_layer! {
    fn raw_schema() => { protocol: ProtocolId::new("raw"), name: "Raw" }
    impl Raw {
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Verbatim bytes",
            get |layer| Some(reflect_get(&layer.bytes)),
            set |layer, value, name| reflect_set(&mut layer.bytes, raw_schema(), name, value),
            layout: (0, length)
        }
    }
    layout fn raw_layout(length: usize);
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Padding {
    pub bytes: Bytes,
    /// First layer index whose declared coverage excludes these bytes.
    /// `None` denotes link padding excluded from every dependent payload.
    pub outside_layer: Option<usize>,
}

impl Padding {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            outside_layer: None,
        }
    }

    pub fn after_layer(bytes: impl Into<Bytes>, outside_layer: usize) -> Self {
        Self {
            bytes: bytes.into(),
            outside_layer: Some(outside_layer),
        }
    }
}

reflective_layer! {
    fn padding_schema() => { protocol: ProtocolId::new("padding"), name: "Padding" }
    impl Padding {
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Trailing padding bytes",
            get |layer| Some(reflect_get(&layer.bytes)),
            set |layer, value, name| reflect_set(&mut layer.bytes, padding_schema(), name, value),
            layout: (0, length)
        },
        "outside_layer" => {
            kind: Unsigned, derived: false, required: false,
            description: "First layer index whose declared length excludes the padding",
            get |layer| layer.outside_layer.map(FieldValue::from),
            set |layer, value, name| match value {
                FieldValue::Unsigned(value) => {
                    layer.outside_layer = Some(usize::try_from(value).map_err(|_| FieldError::OutOfRange {
                        protocol: padding_schema().protocol.clone(), field: name.to_owned(),
                    })?);
                    Ok(())
                }
                _ => Err(FieldError::WrongType {
                    protocol: padding_schema().protocol.clone(), field: name.to_owned(), expected: "unsigned",
                }),
            }
        }
    }
    layout fn padding_layout(length: usize);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MalformedLayer {
    pub intended_protocol: Option<ProtocolId>,
    pub bytes: Bytes,
    pub reason: String,
}

impl MalformedLayer {
    pub fn new(
        intended_protocol: Option<ProtocolId>,
        bytes: impl Into<Bytes>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            intended_protocol,
            bytes: bytes.into(),
            reason: reason.into(),
        }
    }
}

reflective_layer! {
    fn malformed_schema() => { protocol: ProtocolId::new("malformed"), name: "Malformed" }
    impl MalformedLayer {
        "protocol" => {
            kind: Text, derived: false, required: false,
            description: "Intended protocol identifier",
            get |layer| layer.intended_protocol.as_ref().map(|value| FieldValue::Text(value.to_string())),
            set |layer, value, name| match value {
                FieldValue::Text(value) => { layer.intended_protocol = Some(ProtocolId::new(value)); Ok(()) }
                _ => Err(FieldError::WrongType { protocol: malformed_schema().protocol.clone(), field: name.to_owned(), expected: "text" }),
            }
        },
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Preserved malformed bytes",
            get |layer| Some(reflect_get(&layer.bytes)),
            set |layer, value, name| reflect_set(&mut layer.bytes, malformed_schema(), name, value),
            layout: (0, length)
        },
        "reason" => {
            kind: Text, derived: false, required: true,
            description: "Decode or construction finding",
            get |layer| Some(reflect_get(&layer.reason)),
            set |layer, value, name| reflect_set(&mut layer.reason, malformed_schema(), name, value)
        }
    }
    layout fn malformed_layout(length: usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, Default)]
    struct ReflectionHooks {
        value: u8,
    }

    reflective_layer! {
        fn hooks_schema() => { protocol: ProtocolId::new("reflection_hooks"), name: "Reflection hooks" }
        impl ReflectionHooks {
            "value" | "v" => {
                kind: Unsigned, derived: false, required: true,
                description: "Aliased writable value",
                get |layer| Some(reflect_get(&layer.value)),
                set |layer, value, name| reflect_set(&mut layer.value, hooks_schema(), name, value),
                layout: (0, 1)
            },
            "computed" => {
                kind: Unsigned, derived: true, required: false,
                description: "Computed read-only value",
                get |layer| Some(FieldValue::Unsigned(u64::from(layer.value) * 2)),
                set |_layer, _value, name| Err(FieldError::ReadOnly {
                    protocol: hooks_schema().protocol.clone(),
                    field: name.to_owned(),
                })
            }
        }
        layout fn hooks_layout();
    }

    #[test]
    fn declaration_supports_aliases_read_only_fields_and_static_layouts() {
        let mut layer = ReflectionHooks::default();
        layer.set_field("v", FieldValue::Unsigned(7)).unwrap();
        assert_eq!(layer.field("value"), Some(FieldValue::Unsigned(7)));
        assert_eq!(layer.field("v"), Some(FieldValue::Unsigned(7)));
        assert_eq!(layer.field("computed"), Some(FieldValue::Unsigned(14)));
        assert!(matches!(
            layer.set_field("computed", FieldValue::Unsigned(1)),
            Err(FieldError::ReadOnly { .. })
        ));
        assert_eq!(
            hooks_schema()
                .fields
                .iter()
                .map(|field| field.name)
                .collect::<Vec<_>>(),
            vec!["value", "computed"]
        );
        assert_eq!(
            hooks_layout()
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            vec!["value"]
        );
    }
}
