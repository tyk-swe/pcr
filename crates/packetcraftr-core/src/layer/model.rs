// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::borrow::Borrow;
use std::fmt;

use bytes::Bytes;
use serde::Serialize;
use thiserror::Error;

use super::reflection::reflective_layer;
use crate::field::{FieldKind, FieldValue};

/// Static protocol/codec name, cheaply copied. Runtime names from documents,
/// filters, and command lines resolve through
/// [`Registry`](crate::registry::Registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Id(&'static str);

impl Id {
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
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

impl From<&'static str> for Id {
    fn from(value: &'static str) -> Self {
        Self::new(value)
    }
}

display_via_as_str!(Id);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldSchema {
    /// Stable reflective field name used by documents, expressions, and
    /// [`Layer::field`].
    pub name: &'static str,
    /// Additional spellings [`Layer::field`] and [`Layer::set_field`] accept
    /// for this field. Aliases are conveniences, never a second name in the
    /// published contract: only [`Self::name`] is listed by `pcr protocols`
    /// and resolvable as a canonical filter path.
    pub aliases: &'static [&'static str],
    /// Nominal typed value accepted by the field. Derived wire values may also
    /// expose `"auto"` or raw bytes through [`FieldValue`].
    pub kind: FieldKind,
    /// Whether the builder may derive this field from packet context.
    pub derived: bool,
    /// Whether [`Layer::field`] must return a value after defaults. Callers may
    /// omit the field, but constructed, materialized, and decoded layers must
    /// expose it.
    pub required: bool,
    pub description: &'static str,
    /// Named members of an object or of each object in a list.
    #[serde(skip_serializing_if = "<[FieldSchema]>::is_empty")]
    pub children: &'static [Self],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Schema {
    /// Stable protocol identifier.
    pub protocol: Id,
    pub name: &'static str,
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

    /// Reads a registered nested object member or zero-based list element.
    fn field_path(&self, name: &str) -> Option<FieldValue> {
        if let Some(value) = self.field(name) {
            return Some(value);
        }
        let path = name.parse::<crate::field::Path>().ok()?;
        path.schema(self.schema())?;
        path.get(&self.field(path.root())?).cloned()
    }

    /// Edits a nested value through its owning field's validated setter.
    fn set_field_path(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        let unknown = || FieldError::UnknownField {
            protocol: *self.protocol_id(),
            field: name.to_owned(),
        };
        let path = name.parse::<crate::field::Path>().map_err(|_| unknown())?;
        path.schema(self.schema()).ok_or_else(unknown)?;
        if !path.is_nested() {
            return self.set_field(path.root(), value);
        }
        let mut root = self.field(path.root()).ok_or_else(unknown)?;
        if !path.replace(&mut root, value) {
            return Err(unknown());
        }
        self.set_field(path.root(), root)
    }

    /// Validates the stable required-field contract after codec defaults,
    /// materialization, or decoding.
    fn validate_required_fields(&self) -> Result<(), FieldError> {
        for field in self.schema().fields.iter().filter(|field| field.required) {
            if self.field(field.name).is_none() {
                return Err(FieldError::MissingRequired {
                    protocol: *self.protocol_id(),
                    field: field.name.to_owned(),
                });
            }
        }
        Ok(())
    }

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
    pub(crate) fn raw_schema() => { protocol: Id::new("raw"), name: "Raw" }
    impl Raw {
        "bytes" => {
            kind: Bytes, derived: false, required: false,
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
    /// Whether the layer at `layer_index` excludes these bytes from its
    /// payload: link padding is excluded everywhere, and coverage-bounded
    /// padding from the layer that declared the boundary onward.
    pub fn excluded_from(&self, layer_index: usize) -> bool {
        self.outside_layer
            .is_none_or(|outside_layer| layer_index >= outside_layer)
    }

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
    pub(crate) fn padding_schema() => { protocol: Id::new("padding"), name: "Padding" }
    impl Padding {
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Trailing padding bytes",
            reflect: bytes,
            layout: (0, length)
        },
        "outside_layer" => {
            kind: Unsigned, derived: false, required: false,
            description: "First layer index whose declared length excludes the padding",
            get |layer| layer.outside_layer.map(FieldValue::from),
            set |layer, value, name| match value {
                FieldValue::Unsigned(value) => {
                    layer.outside_layer = Some(usize::try_from(value).map_err(|_| FieldError::OutOfRange {
                        protocol: padding_schema().protocol, field: name.to_owned(),
                    })?);
                    Ok(())
                }
                _ => Err(FieldError::WrongType {
                    protocol: padding_schema().protocol, field: name.to_owned(), expected: "unsigned",
                }),
            }
        }
    }
    layout pub(crate) fn padding_layout(length: usize);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Malformed {
    pub intended_protocol: Option<String>,
    pub bytes: Bytes,
    pub reason: String,
}

impl Malformed {
    pub fn new(
        intended_protocol: Option<String>,
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
    pub(crate) fn malformed_schema() => { protocol: Id::new("malformed"), name: "Malformed" }
    impl Malformed {
        "protocol" => {
            kind: Text, derived: false, required: false,
            description: "Intended protocol identifier",
            get |layer| layer.intended_protocol.clone().map(FieldValue::Text),
            set |layer, value, name| match value {
                FieldValue::Text(value) => { layer.intended_protocol = Some(value); Ok(()) }
                _ => Err(FieldError::WrongType { protocol: malformed_schema().protocol, field: name.to_owned(), expected: "text" }),
            }
        },
        "bytes" => {
            kind: Bytes, derived: false, required: false,
            description: "Preserved malformed bytes",
            reflect: bytes,
            layout: (0, length)
        },
        "reason" => {
            kind: Text, derived: false, required: true,
            description: "Decode or construction finding",
            reflect: reason
        }
    }
    layout pub(crate) fn malformed_layout(length: usize);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::ByteRange;

    #[test]
    fn opaque_layouts_cover_the_whole_input() {
        assert_eq!(padding_layout(2)[0].range, ByteRange::new(0, 2));
        assert_eq!(malformed_layout(4)[0].range, ByteRange::new(0, 4));
    }
}
