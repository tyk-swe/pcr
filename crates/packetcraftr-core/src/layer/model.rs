// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::borrow::Borrow;
use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::super::field::{FieldKind, FieldValue, WireValue};
use super::reflection::reflective_layer;

/// An open, stable identifier for a protocol layer or codec.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id(String);

impl Id {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Id {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for Id {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for Id {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Id {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Must be present after codec defaults; documents must spell it.
    Required,
    /// A wire value the builder computes (`auto`) unless a literal is given.
    Derived,
    /// Has a constant default (`FieldSchema::default`) when omitted.
    Optional,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldSchema {
    /// Stable reflective field name used by documents, expressions, and
    /// [`Layer::field`].
    pub name: &'static str,
    /// Nominal typed value accepted by the field. Derived wire values may also
    /// expose `"auto"` or raw bytes through [`FieldValue`].
    pub kind: FieldKind,
    /// Whether the field is required, derived, or optional with a constant default.
    pub tier: Tier,
    /// v2 text form of the value `Layer::default()` produces. `Some` for an
    /// Optional field with a constant default; `None` for Required and Derived
    /// fields, and for Optional fields that are simply absent when omitted
    /// (such as an optional GRE key).
    pub default: Option<&'static str>,
    /// Alternative spellings accepted on input; emission uses `name`.
    pub aliases: &'static [&'static str],
    /// Element kind for `FieldKind::List` fields; `None` otherwise.
    pub element: Option<FieldKind>,
    /// Inclusive upper bound for Unsigned fields (from the setter's integer type or the `reflect_bounded` maximum); `None` for other kinds.
    pub max: Option<u64>,
    /// Human-readable field purpose.
    pub description: &'static str,
}

impl FieldSchema {
    pub fn is_derived(&self) -> bool {
        self.tier == Tier::Derived
    }

    pub fn is_required(&self) -> bool {
        self.tier == Tier::Required
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Schema {
    /// Stable protocol identifier.
    pub protocol: Id,
    /// Human-readable protocol name.
    pub name: &'static str,
    /// Every setter is read-only; the layer decodes but cannot be built from a document.
    pub decode_only: bool,
    /// Ordered reflective fields.
    pub fields: &'static [FieldSchema],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldError {
    #[error("layer {protocol} has no field named {field}")]
    UnknownField { protocol: Id, field: String },
    #[error("field {field} on layer {protocol} expected {expected}")]
    WrongType {
        protocol: Id,
        field: String,
        expected: &'static str,
    },
    #[error("field {field} on layer {protocol} is outside the allowed range")]
    OutOfRange { protocol: Id, field: String },
    #[error("field {field} on layer {protocol} cannot be edited reflectively")]
    ReadOnly { protocol: Id, field: String },
    #[error("required field {field} is absent from layer {protocol} after defaults")]
    MissingRequired { protocol: Id, field: String },
}

/// Object-safe packet layer interface used by built-in and external protocols.
pub trait Layer: Any + Send + Sync + fmt::Debug {
    fn schema(&self) -> &'static Schema;
    fn clone_box(&self) -> Box<dyn Layer>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn field(&self, name: &str) -> Option<FieldValue>;
    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError>;
    fn wire_field(&self, _name: &str) -> Option<WireValue<u64>> {
        None
    }

    /// Validates the stable required-field contract after codec defaults,
    /// materialization, or decoding.
    fn validate_required_fields(&self) -> Result<(), FieldError> {
        if self.schema().decode_only {
            return Ok(());
        }
        for field in self
            .schema()
            .fields
            .iter()
            .filter(|field| field.is_required())
        {
            if self.field(field.name).is_none() {
                return Err(FieldError::MissingRequired {
                    protocol: self.protocol_id().clone(),
                    field: field.name.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Returns the stable protocol identifier stored by this layer's schema.
    fn protocol_id(&self) -> &Id {
        &self.schema().protocol
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
    fn raw_schema() => { protocol: Id::new("raw"), name: "Raw" }
    impl Raw {
        "bytes" => {
            kind: Bytes, tier: Optional, default: "0x",
            description: "Verbatim bytes",
            reflect: bytes,
            layout: (0, length)
        }
    }
    layout pub fn raw_layout(length: usize);
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
    fn padding_schema() => { protocol: Id::new("padding"), name: "Padding" }
    impl Padding {
        "bytes" => {
            kind: Bytes, tier: Optional, default: "0x",
            description: "Trailing padding bytes",
            reflect: bytes,
            layout: (0, length)
        },
        "outside_layer" => {
            kind: Unsigned, tier: Optional, max: u64::MAX,
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
    layout pub fn padding_layout(length: usize);
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Malformed {
    pub intended_protocol: Option<Id>,
    pub bytes: Bytes,
    pub reason: String,
}

impl Malformed {
    pub fn new(
        intended_protocol: Option<Id>,
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
    fn malformed_schema() => { protocol: Id::new("malformed"), name: "Malformed" }
    impl Malformed {
        "protocol" => {
            kind: Text, tier: Optional,
            description: "Intended protocol identifier",
            get |layer| layer.intended_protocol.as_ref().map(|value| FieldValue::Text(value.to_string())),
            set |layer, value, name| match value {
                FieldValue::Text(value) => { layer.intended_protocol = Some(Id::new(value)); Ok(()) }
                _ => Err(FieldError::WrongType { protocol: malformed_schema().protocol.clone(), field: name.to_owned(), expected: "text" }),
            }
        },
        "bytes" => {
            kind: Bytes, tier: Optional, default: "0x",
            description: "Preserved malformed bytes",
            reflect: bytes,
            layout: (0, length)
        },
        "reason" => {
            kind: Text, tier: Required,
            description: "Decode or construction finding",
            reflect: reason
        }
    }
    layout pub fn malformed_layout(length: usize);
}
