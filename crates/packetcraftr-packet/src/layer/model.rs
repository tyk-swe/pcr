// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::fmt;

use bytes::Bytes;
use packetcraftr_model::{FieldId, ProtocolId};
use thiserror::Error;

use super::super::field::{FieldKind, FieldValue};
use super::reflection::{reflect_get, reflect_set, reflective_layer};
use super::schema::LayerSchema;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldError {
    #[error("layer {protocol} has no field named {field}")]
    UnknownField { protocol: ProtocolId, field: String },
    #[error("layer {protocol} has no field with ID {field}")]
    UnknownFieldId {
        protocol: ProtocolId,
        field: FieldId,
    },
    #[error("field {field} on layer {protocol} was supplied more than once")]
    DuplicateField {
        protocol: ProtocolId,
        field: FieldId,
    },
    #[error("field {field} on layer {protocol} expected {expected}")]
    WrongType {
        protocol: ProtocolId,
        field: String,
        expected: &'static str,
    },
    #[error("field {field} on layer {protocol} expected {expected:?}, got {actual:?}")]
    WrongKind {
        protocol: ProtocolId,
        field: FieldId,
        expected: FieldKind,
        actual: FieldKind,
    },
    #[error("field {field} on layer {protocol} is outside the allowed range")]
    OutOfRange { protocol: ProtocolId, field: String },
    #[error("field {field} on layer {protocol} violates its constraints")]
    Constraint {
        protocol: ProtocolId,
        field: FieldId,
    },
    #[error("field {field} on layer {protocol} cannot be edited reflectively")]
    ReadOnly { protocol: ProtocolId, field: String },
    #[error("required field {field} is absent from layer {protocol} after defaults")]
    MissingRequired {
        protocol: ProtocolId,
        field: FieldId,
    },
}

/// Object-safe packet layer interface used by built-in and external protocols.
pub trait Layer: Any + Send + Sync + fmt::Debug {
    fn schema(&self) -> &LayerSchema;
    fn clone_box(&self) -> Box<dyn Layer>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn field_by_id(&self, id: &FieldId) -> Option<FieldValue>;
    fn set_field_by_id(&mut self, id: &FieldId, value: FieldValue) -> Result<(), FieldError>;

    /// Convenience lookup through the schema's normalized name and alias map.
    fn field(&self, name: &str) -> Option<FieldValue> {
        let id = self.schema().canonical_field_id(name)?;
        self.field_by_id(id)
    }

    /// Convenience update through the schema's normalized name and alias map.
    fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), FieldError> {
        let Some(id) = self.schema().canonical_field_id(name).cloned() else {
            return Err(FieldError::UnknownField {
                protocol: self.protocol_id().clone(),
                field: name.to_owned(),
            });
        };
        self.set_field_by_id(&id, value)
    }

    /// Validates the stable required-field contract after codec defaults,
    /// materialization, or decoding.
    fn validate_required_fields(&self) -> Result<(), FieldError> {
        for field in self.schema().fields.iter().filter(|field| field.required) {
            if self.field_by_id(&field.id).is_none() {
                return Err(FieldError::MissingRequired {
                    protocol: self.protocol_id().clone(),
                    field: field.id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Returns the stable protocol identifier stored by this layer's schema.
    fn protocol_id(&self) -> &ProtocolId {
        &self.schema().protocol
    }

    /// Reset dependent values to automatic derivation.
    fn normalize(&mut self) {}

    /// Names the schema fields that declare a static byte range, in schema
    /// order. Reflective declarations answer from their layout constructor;
    /// codecs that compute layouts dynamically report none.
    ///
    /// Protocol crates use this to prove that a published support manifest and
    /// a layer's declared layout cannot drift apart.
    fn declared_layout_fields(&self) -> Vec<FieldId> {
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
    fn raw_schema() => { protocol: ProtocolId::from_static("raw"), name: "Raw", aliases: ["payload", "bytes"] }
    impl Raw {
        "bytes" => {
            id: "bytes", kind: Bytes, derived: false, required: false,
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
    fn padding_schema() => { protocol: ProtocolId::from_static("padding"), name: "Padding", aliases: ["pad"] }
    impl Padding {
        "bytes" => {
            id: "bytes", kind: Bytes, derived: false, required: false,
            description: "Trailing padding bytes",
            get |layer| Some(reflect_get(&layer.bytes)),
            set |layer, value, name| reflect_set(&mut layer.bytes, padding_schema(), name, value),
            layout: (0, length)
        },
        "outside_layer" => {
            id: "outside_layer", kind: Unsigned, derived: false, required: false,
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
    fn malformed_schema() => { protocol: ProtocolId::from_static("malformed"), name: "Malformed" }
    impl MalformedLayer {
        "protocol" => {
            id: "protocol", kind: Text, derived: false, required: false,
            description: "Intended protocol identifier",
            get |layer| layer.intended_protocol.as_ref().map(|value| FieldValue::Text(value.to_string())),
            set |layer, value, name| match value {
                FieldValue::Text(value) => {
                    layer.intended_protocol = Some(ProtocolId::new(value).map_err(|_| {
                        FieldError::OutOfRange {
                            protocol: malformed_schema().protocol.clone(),
                            field: name.to_owned(),
                        }
                    })?);
                    Ok(())
                }
                _ => Err(FieldError::WrongType { protocol: malformed_schema().protocol.clone(), field: name.to_owned(), expected: "text" }),
            }
        },
        "bytes" => {
            id: "bytes", kind: Bytes, derived: false, required: false,
            description: "Preserved malformed bytes",
            get |layer| Some(reflect_get(&layer.bytes)),
            set |layer, value, name| reflect_set(&mut layer.bytes, malformed_schema(), name, value),
            layout: (0, length)
        },
        "reason" => {
            id: "reason", kind: Text, derived: false, required: true,
            description: "Decode or construction finding",
            get |layer| Some(reflect_get(&layer.reason)),
            set |layer, value, name| reflect_set(&mut layer.reason, malformed_schema(), name, value)
        }
    }
    layout fn malformed_layout(length: usize);
}

#[cfg(test)]
mod tests {
    // `reflective_layer!` emits a `pub` layout constructor because protocol
    // crates invoke it from their own module roots; inside this private test
    // module that visibility is deliberately unreachable.
    #![allow(unreachable_pub)]

    use std::collections::HashMap;

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct ReflectionHooks {
        value: u8,
    }

    reflective_layer! {
        fn hooks_schema() => { protocol: ProtocolId::from_static("reflection_hooks"), name: "Reflection hooks" }
        impl ReflectionHooks {
            "value" | "v" => {
                id: "value", kind: Unsigned, derived: false, required: true,
                description: "Aliased writable value",
                get |layer| Some(reflect_get(&layer.value)),
                set |layer, value, name| reflect_set(&mut layer.value, hooks_schema(), name, value),
                layout: (0, 1)
            },
            "computed" => {
                id: "computed", kind: Unsigned, derived: true, required: false,
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
                .map(|field| field.name.as_ref())
                .collect::<Vec<_>>(),
            vec!["value", "computed"]
        );
        assert_eq!(
            hooks_layout()
                .iter()
                .map(|field| field.id.as_str())
                .collect::<Vec<_>>(),
            vec!["value"]
        );
    }

    #[test]
    fn protocol_identity_is_borrowed_from_the_owned_shared_schema() {
        let layer = ReflectionHooks::default();
        let first = layer.protocol_id();
        let second = layer.protocol_id();

        assert!(std::ptr::eq(first, &layer.schema().protocol));
        assert!(std::ptr::eq(first, second));
    }

    #[test]
    fn protocol_id_supports_borrowed_hash_map_lookup() {
        let mut protocols = HashMap::new();
        protocols.insert(ProtocolId::from_static("ipv4"), 4);

        assert_eq!(protocols.get("ipv4"), Some(&4));
    }

    #[test]
    fn protocol_id_serialization_remains_transparent() {
        assert_eq!(
            serde_json::to_string(&ProtocolId::from_static("example.protocol")).unwrap(),
            "\"example.protocol\""
        );
    }
}
