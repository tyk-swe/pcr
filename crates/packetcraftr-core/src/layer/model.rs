// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::borrow::Borrow;
use std::fmt;

use serde::Serialize;

use crate::field::{self, FieldKind, FieldValue, Path};

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
    pub name: &'static str,
    /// Aliases are conveniences, never a second name in the published contract.
    pub aliases: &'static [&'static str],
    pub kind: FieldKind,
    pub derived: bool,
    pub required: bool,
    pub description: &'static str,
    #[serde(skip_serializing_if = "<[FieldSchema]>::is_empty")]
    pub children: &'static [Self],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Schema {
    pub protocol: Id,
    pub name: &'static str,
    pub fields: &'static [FieldSchema],
}

pub trait Layer: Any + Send + Sync + fmt::Debug {
    fn schema(&self) -> &'static Schema;
    fn clone_box(&self) -> Box<dyn Layer>;
    fn field(&self, name: &str) -> Option<FieldValue>;
    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), field::Error>;

    fn field_path(&self, path: &Path) -> Option<FieldValue> {
        if !path.is_nested() {
            return self.field(path.root());
        }
        path.schema(self.schema())?;
        path.get(&self.field(path.root())?).cloned()
    }

    fn set_field_path(&mut self, path: &Path, value: FieldValue) -> Result<(), field::Error> {
        let unknown = || field::Error::UnknownField {
            protocol: *self.protocol_id(),
            field: path.to_string(),
        };
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
    pub fn is<T: Layer>(&self) -> bool {
        (self as &dyn Any).is::<T>()
    }

    pub fn downcast_ref<T: Layer>(&self) -> Option<&T> {
        (self as &dyn Any).downcast_ref()
    }

    pub fn downcast_mut<T: Layer>(&mut self) -> Option<&mut T> {
        (self as &mut dyn Any).downcast_mut()
    }
}

impl Clone for Box<dyn Layer> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
