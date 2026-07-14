// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::fmt;
use std::sync::OnceLock;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::super::field::{FieldKind, FieldValue};

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

fn raw_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[FieldSchema {
        name: "bytes",
        kind: FieldKind::Bytes,
        derived: false,
        required: false,
        description: "Verbatim bytes",
    }];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: ProtocolId::new("raw"),
        name: "Raw",
        fields: FIELDS,
    })
}

impl Layer for Raw {
    fn schema(&self) -> &'static LayerSchema {
        raw_schema()
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, name: &str) -> Option<FieldValue> {
        (name == "bytes").then(|| FieldValue::Bytes(self.bytes.clone()))
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        if name != "bytes" {
            return Err(unknown_field(self, name));
        }
        let FieldValue::Bytes(bytes) = value else {
            return Err(wrong_type(self, name, "bytes"));
        };
        self.bytes = bytes;
        Ok(())
    }
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

fn padding_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "bytes",
            kind: FieldKind::Bytes,
            derived: false,
            required: false,
            description: "Trailing padding bytes",
        },
        FieldSchema {
            name: "outside_layer",
            kind: FieldKind::Unsigned,
            derived: false,
            required: false,
            description: "First layer index whose declared length excludes the padding",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: ProtocolId::new("padding"),
        name: "Padding",
        fields: FIELDS,
    })
}

impl Layer for Padding {
    fn schema(&self) -> &'static LayerSchema {
        padding_schema()
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "bytes" => Some(FieldValue::Bytes(self.bytes.clone())),
            "outside_layer" => self
                .outside_layer
                .map(|value| FieldValue::Unsigned(value as u64)),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("bytes", FieldValue::Bytes(bytes)) => self.bytes = bytes,
            ("outside_layer", FieldValue::Unsigned(value)) => {
                self.outside_layer = Some(
                    usize::try_from(value)
                        .map_err(|_| out_of_range_layer(self, "outside_layer"))?,
                );
            }
            ("bytes", _) => return Err(wrong_type(self, name, "bytes")),
            ("outside_layer", _) => return Err(wrong_type(self, name, "unsigned")),
            _ => return Err(unknown_field(self, name)),
        }
        Ok(())
    }
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

fn malformed_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "protocol",
            kind: FieldKind::Text,
            derived: false,
            required: false,
            description: "Intended protocol identifier",
        },
        FieldSchema {
            name: "bytes",
            kind: FieldKind::Bytes,
            derived: false,
            required: false,
            description: "Preserved malformed bytes",
        },
        FieldSchema {
            name: "reason",
            kind: FieldKind::Text,
            derived: false,
            required: true,
            description: "Decode or construction finding",
        },
    ];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: ProtocolId::new("malformed"),
        name: "Malformed",
        fields: FIELDS,
    })
}

impl Layer for MalformedLayer {
    fn schema(&self) -> &'static LayerSchema {
        malformed_schema()
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, name: &str) -> Option<FieldValue> {
        match name {
            "protocol" => self
                .intended_protocol
                .as_ref()
                .map(|value| FieldValue::Text(value.to_string())),
            "bytes" => Some(FieldValue::Bytes(self.bytes.clone())),
            "reason" => Some(FieldValue::Text(self.reason.clone())),
            _ => None,
        }
    }

    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        match (name, value) {
            ("protocol", FieldValue::Text(value)) => {
                self.intended_protocol = Some(ProtocolId::new(value));
                Ok(())
            }
            ("bytes", FieldValue::Bytes(value)) => {
                self.bytes = value;
                Ok(())
            }
            ("reason", FieldValue::Text(value)) => {
                self.reason = value;
                Ok(())
            }
            ("protocol" | "reason", _) => Err(wrong_type(self, name, "text")),
            ("bytes", _) => Err(wrong_type(self, name, "bytes")),
            _ => Err(unknown_field(self, name)),
        }
    }
}

pub(crate) fn unknown_field(layer: &dyn Layer, field: &str) -> FieldError {
    FieldError::UnknownField {
        protocol: layer.protocol_id(),
        field: field.to_owned(),
    }
}

pub(crate) fn wrong_type(layer: &dyn Layer, field: &str, expected: &'static str) -> FieldError {
    FieldError::WrongType {
        protocol: layer.protocol_id(),
        field: field.to_owned(),
        expected,
    }
}

fn out_of_range_layer(layer: &dyn Layer, field: &str) -> FieldError {
    FieldError::OutOfRange {
        protocol: layer.protocol_id(),
        field: field.to_owned(),
    }
}
