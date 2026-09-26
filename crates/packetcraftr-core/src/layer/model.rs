// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::borrow::Borrow;
use std::fmt;

use serde::Serialize;

use crate::field::{self, FieldKind, FieldValue};

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

/// Object-safe packet layer interface used by built-in and external protocols.
///
/// `dyn Layer` upcasts to `dyn Any`; its inherent `is`, `downcast_ref`, and
/// `downcast_mut` recover the concrete layer.
pub trait Layer: Any + Send + Sync + fmt::Debug {
    fn schema(&self) -> &'static Schema;
    /// Clones the layer behind a trait object. `Clone` requires `Sized` and
    /// cannot be a supertrait of an object-safe trait, so `Box<dyn Layer>`
    /// needs this method to implement `Clone`.
    fn clone_box(&self) -> Box<dyn Layer>;
    fn field(&self, name: &str) -> Option<FieldValue>;
    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), field::Error>;

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
    fn set_field_path(&mut self, name: &str, value: FieldValue) -> Result<(), field::Error> {
        let unknown = || field::Error::UnknownField {
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
    fn validate_required_fields(&self) -> Result<(), field::Error> {
        for field in self.schema().fields.iter().filter(|field| field.required) {
            if self.field(field.name).is_none() {
                return Err(field::Error::MissingRequired {
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

impl dyn Layer {
    /// Returns whether the concrete layer is `T`.
    pub fn is<T: Layer>(&self) -> bool {
        (self as &dyn Any).is::<T>()
    }

    /// Returns the concrete layer when it is `T`.
    pub fn downcast_ref<T: Layer>(&self) -> Option<&T> {
        (self as &dyn Any).downcast_ref()
    }

    /// Returns the concrete layer mutably when it is `T`.
    pub fn downcast_mut<T: Layer>(&mut self) -> Option<&mut T> {
        (self as &mut dyn Any).downcast_mut()
    }
}

impl Clone for Box<dyn Layer> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
