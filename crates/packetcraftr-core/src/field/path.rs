// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded paths shared by reflective readers and editors.

use super::FieldValue;
use crate::layer::{FieldSchema, Schema};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Component {
    Name(String),
    Index(usize),
}

/// A layer-relative path such as `questions[0].name`.
/// List indices are zero based; a path may contain at most 64 components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    root: String,
    components: Vec<Component>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid reflective field path {path:?}")]
pub struct PathError {
    pub path: String,
}

impl std::str::FromStr for Path {
    type Err = PathError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let invalid = || PathError {
            path: input.chars().take(256).collect(),
        };
        if input.is_empty() || input.len() > 8192 {
            return Err(invalid());
        }
        let mut rest = input;
        let name = |text: &str| {
            text.bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count()
        };
        let length = name(rest);
        if length == 0 {
            return Err(invalid());
        }
        let root = rest[..length].to_owned();
        rest = &rest[length..];
        let mut components = Vec::new();
        while !rest.is_empty() {
            if components.len() >= 63 {
                return Err(invalid());
            }
            if let Some(tail) = rest.strip_prefix('.') {
                let length = name(tail);
                if length == 0 {
                    return Err(invalid());
                }
                components.push(Component::Name(tail[..length].to_owned()));
                rest = &tail[length..];
            } else if let Some(tail) = rest.strip_prefix('[') {
                let Some(end) = tail.find(']') else {
                    return Err(invalid());
                };
                let digits = &tail[..end];
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                components.push(Component::Index(digits.parse().map_err(|_| invalid())?));
                rest = &tail[end + 1..];
            } else {
                return Err(invalid());
            }
        }
        Ok(Self { root, components })
    }
}

impl Path {
    pub fn root(&self) -> &str {
        &self.root
    }
    pub fn is_nested(&self) -> bool {
        !self.components.is_empty()
    }

    /// Normalizes a resolved root alias and numeric indices for duplicate checks.
    pub(crate) fn canonical(&self, root: &str) -> String {
        let mut path = root.to_owned();
        for component in &self.components {
            match component {
                Component::Name(name) => {
                    path.push('.');
                    path.push_str(name);
                }
                Component::Index(index) => {
                    path.push('[');
                    path.push_str(&index.to_string());
                    path.push(']');
                }
            }
        }
        path
    }

    /// Resolves declared members; indices address an element of a list field.
    pub fn schema<'a>(&self, schema: &'a Schema) -> Option<&'a FieldSchema> {
        let mut field = schema
            .fields
            .iter()
            .find(|field| field.name == self.root || field.aliases.contains(&self.root.as_str()))?;
        let mut element = false;
        for part in &self.components {
            match part {
                Component::Name(name) => {
                    if field.kind != super::FieldKind::Object
                        && !(field.kind == super::FieldKind::List && element)
                    {
                        return None;
                    }
                    field = field.children.iter().find(|child| child.name == name)?;
                    element = false;
                }
                Component::Index(_) if field.kind == super::FieldKind::List && !element => {
                    element = true;
                }
                Component::Index(_) => return None,
            }
        }
        Some(field)
    }

    pub fn get<'a>(&self, root: &'a FieldValue) -> Option<&'a FieldValue> {
        let mut value = root;
        for component in &self.components {
            value = match (component, value) {
                (Component::Name(name), FieldValue::Object(values)) => values.get(name)?,
                (Component::Index(index), FieldValue::List(values)) => values.get(*index)?,
                _ => return None,
            };
        }
        Some(value)
    }

    /// Atomically replaces an existing member; never creates unspecified keys or indices.
    pub fn replace(&self, root: &mut FieldValue, replacement: FieldValue) -> bool {
        let mut value = root;
        for component in &self.components {
            let next = match (component, value) {
                (Component::Name(name), FieldValue::Object(values)) => values.get_mut(name),
                (Component::Index(index), FieldValue::List(values)) => values.get_mut(*index),
                _ => None,
            };
            let Some(next) = next else {
                return false;
            };
            value = next;
        }
        *value = replacement;
        true
    }
}
