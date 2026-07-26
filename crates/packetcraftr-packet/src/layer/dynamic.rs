// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Host-owned dynamic packet layers.

use std::any::Any;
use std::sync::Arc;

use packetcraftr_model::FieldId;

use super::{FieldError, FieldSetError, Layer, LayerSchema, ValidatedFieldSet};
use crate::field::FieldValue;

/// A validated layer whose values occupy deterministic schema slots.
#[derive(Clone, PartialEq, Eq)]
pub struct DynamicLayer {
    schema: Arc<LayerSchema>,
    values: Vec<Option<FieldValue>>,
}

impl DynamicLayer {
    pub fn new(
        schema: Arc<LayerSchema>,
        fields: impl IntoIterator<Item = (FieldId, FieldValue)>,
    ) -> Result<Self, FieldError> {
        Self::from_validated(ValidatedFieldSet::from_ids(schema, fields)?)
    }

    pub fn from_named(
        schema: Arc<LayerSchema>,
        fields: impl IntoIterator<Item = (impl AsRef<str>, FieldValue)>,
    ) -> Result<Self, FieldError> {
        Self::from_validated(ValidatedFieldSet::from_names(schema, fields)?)
    }

    pub fn from_validated(fields: ValidatedFieldSet) -> Result<Self, FieldError> {
        let (schema, values) = fields.into_parts();
        for (slot, field) in schema.fields.iter().enumerate() {
            if field.required && values[slot].is_none() {
                return Err(FieldError::MissingRequired {
                    protocol: schema.protocol.clone(),
                    field: field.id.clone(),
                });
            }
        }
        Ok(Self { schema, values })
    }
}

impl std::fmt::Debug for DynamicLayer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = formatter.debug_struct("DynamicLayer");
        output.field("protocol", &self.schema.protocol);
        for (field, value) in self.schema.fields.iter().zip(&self.values) {
            if let Some(value) = value {
                output.field(field.name.as_ref(), value);
            }
        }
        output.finish()
    }
}

impl Layer for DynamicLayer {
    fn schema(&self) -> &LayerSchema {
        &self.schema
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

    fn field_by_id(&self, id: &FieldId) -> Option<FieldValue> {
        self.schema
            .field_slot(id)
            .and_then(|slot| self.values.get(slot))
            .and_then(Clone::clone)
    }

    fn set_field_by_id(&mut self, id: &FieldId, value: FieldValue) -> Result<(), FieldError> {
        let Some(slot) = self.schema.field_slot(id) else {
            return Err(FieldError::UnknownFieldId {
                protocol: self.schema.protocol.clone(),
                field: id.clone(),
            });
        };
        let field = &self.schema.fields[slot];
        if !field.accepts_kind(&value) {
            return Err(FieldError::WrongKind {
                protocol: self.schema.protocol.clone(),
                field: field.id.clone(),
                expected: field.kind,
                actual: value.kind(),
            });
        }
        if !field.accepts(&value) {
            return Err(FieldError::Constraint {
                protocol: self.schema.protocol.clone(),
                field: field.id.clone(),
            });
        }
        self.values[slot] = Some(value);
        Ok(())
    }
}

impl From<FieldSetError> for FieldError {
    fn from(error: FieldSetError) -> Self {
        match error {
            FieldSetError::UnknownField { protocol, field } => {
                Self::UnknownField { protocol, field }
            }
            FieldSetError::UnknownFieldId { protocol, field } => {
                Self::UnknownFieldId { protocol, field }
            }
            FieldSetError::DuplicateField { protocol, field } => {
                Self::DuplicateField { protocol, field }
            }
            FieldSetError::WrongKind {
                protocol,
                field,
                expected,
                actual,
            } => Self::WrongKind {
                protocol,
                field,
                expected,
                actual,
            },
            FieldSetError::Constraint { protocol, field } => Self::Constraint { protocol, field },
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::field::FieldKind;
    use crate::layer::{FieldConstraints, FieldSchema, LengthRange, SchemaError};

    fn field(
        id: &'static str,
        name: &'static str,
        aliases: impl IntoIterator<Item = &'static str>,
        kind: FieldKind,
        required: bool,
        constraints: FieldConstraints,
    ) -> FieldSchema {
        FieldSchema::new(
            FieldId::from_static(id),
            name,
            aliases,
            kind,
            required,
            false,
            format!("{name} test field"),
            constraints,
        )
        .unwrap()
    }

    fn schema(fields: impl IntoIterator<Item = FieldSchema>) -> Arc<LayerSchema> {
        Arc::new(
            LayerSchema::new(
                packetcraftr_model::ProtocolId::from_static("test.dynamic"),
                "Dynamic test",
                ["DYN"],
                7,
                fields,
            )
            .unwrap(),
        )
    }

    #[test]
    fn malformed_schemas_reject_duplicate_ids_names_and_aliases() {
        let duplicate_id = LayerSchema::new(
            packetcraftr_model::ProtocolId::from_static("test.duplicate_id"),
            "Duplicate ID",
            std::iter::empty::<&str>(),
            1,
            [
                field(
                    "same",
                    "first",
                    [],
                    FieldKind::Unsigned,
                    false,
                    FieldConstraints::default(),
                ),
                field(
                    "same",
                    "second",
                    [],
                    FieldKind::Unsigned,
                    false,
                    FieldConstraints::default(),
                ),
            ],
        );
        assert!(matches!(
            duplicate_id,
            Err(SchemaError::DuplicateFieldId { .. })
        ));

        let duplicate_name = LayerSchema::new(
            packetcraftr_model::ProtocolId::from_static("test.duplicate_name"),
            "Duplicate name",
            std::iter::empty::<&str>(),
            1,
            [
                field(
                    "first",
                    "first",
                    ["shared"],
                    FieldKind::Unsigned,
                    false,
                    FieldConstraints::default(),
                ),
                field(
                    "second",
                    "shared",
                    [],
                    FieldKind::Unsigned,
                    false,
                    FieldConstraints::default(),
                ),
            ],
        );
        assert!(matches!(
            duplicate_name,
            Err(SchemaError::DuplicateFieldName { .. })
        ));

        assert!(matches!(
            FieldSchema::new(
                FieldId::from_static("field"),
                "field",
                [" FIELD "],
                FieldKind::Bool,
                false,
                false,
                "duplicate alias",
                FieldConstraints::default(),
            ),
            Err(SchemaError::AliasMatchesCanonical { .. })
        ));
        assert!(matches!(
            FieldSchema::new(
                FieldId::from_static("field"),
                "field",
                ["alias", " ALIAS "],
                FieldKind::Bool,
                false,
                false,
                "duplicate alias",
                FieldConstraints::default(),
            ),
            Err(SchemaError::DuplicateAlias { .. })
        ));

        let mut manually_modified = field(
            "first",
            "first",
            [],
            FieldKind::Unsigned,
            false,
            FieldConstraints::default(),
        );
        manually_modified.name = Arc::from(" SHARED ");
        assert!(matches!(
            LayerSchema::new(
                packetcraftr_model::ProtocolId::from_static("test.normalized_duplicate"),
                "Normalized duplicate",
                std::iter::empty::<&str>(),
                1,
                [
                    manually_modified,
                    field(
                        "second",
                        "shared",
                        [],
                        FieldKind::Unsigned,
                        false,
                        FieldConstraints::default(),
                    ),
                ],
            ),
            Err(SchemaError::DuplicateFieldName { .. })
        ));
    }

    #[test]
    fn construction_rejects_missing_unknown_duplicate_and_wrong_kind_values() {
        let schema = schema([field(
            "count",
            "count",
            ["n"],
            FieldKind::Unsigned,
            true,
            FieldConstraints::unsigned(1, 10),
        )]);

        assert!(matches!(
            DynamicLayer::new(Arc::clone(&schema), []),
            Err(FieldError::MissingRequired { .. })
        ));
        assert!(matches!(
            DynamicLayer::new(
                Arc::clone(&schema),
                [(FieldId::from_static("missing"), FieldValue::Unsigned(1))]
            ),
            Err(FieldError::UnknownFieldId { .. })
        ));
        assert!(matches!(
            DynamicLayer::from_named(
                Arc::clone(&schema),
                [
                    ("count", FieldValue::Unsigned(1)),
                    ("n", FieldValue::Unsigned(2))
                ]
            ),
            Err(FieldError::DuplicateField { .. })
        ));
        assert!(matches!(
            DynamicLayer::from_named(
                Arc::clone(&schema),
                [("count", FieldValue::Text("wrong".to_owned()))]
            ),
            Err(FieldError::WrongKind { .. })
        ));
        assert!(matches!(
            DynamicLayer::from_named(schema, [("count", FieldValue::Unsigned(11))]),
            Err(FieldError::Constraint { .. })
        ));
    }

    #[test]
    fn bounded_numeric_text_byte_and_list_constraints_are_enforced() {
        let schema = schema([
            field(
                "number",
                "number",
                [],
                FieldKind::Unsigned,
                true,
                FieldConstraints::unsigned(2, 4),
            ),
            field(
                "text",
                "text",
                [],
                FieldKind::Text,
                true,
                FieldConstraints::text_bytes(2, 4),
            ),
            field(
                "bytes",
                "bytes",
                [],
                FieldKind::Bytes,
                true,
                FieldConstraints::byte_length(1, 2),
            ),
            field(
                "list",
                "list",
                [],
                FieldKind::List,
                true,
                FieldConstraints::list_length(1, 2),
            ),
        ]);
        let valid = [
            ("number", FieldValue::Unsigned(3)),
            ("text", FieldValue::Text("four".to_owned())),
            ("bytes", FieldValue::Bytes(Bytes::from_static(&[1, 2]))),
            ("list", FieldValue::List(vec![FieldValue::Bool(true)])),
        ];
        DynamicLayer::from_named(Arc::clone(&schema), valid).unwrap();

        for invalid in [
            ("number", FieldValue::Unsigned(5)),
            ("text", FieldValue::Text("oversized".to_owned())),
            ("bytes", FieldValue::Bytes(Bytes::from_static(&[1, 2, 3]))),
            ("list", FieldValue::List(Vec::new())),
        ] {
            let values = [
                ("number", FieldValue::Unsigned(3)),
                ("text", FieldValue::Text("four".to_owned())),
                ("bytes", FieldValue::Bytes(Bytes::from_static(&[1, 2]))),
                ("list", FieldValue::List(vec![FieldValue::Bool(true)])),
            ]
            .into_iter()
            .map(|entry| {
                if entry.0 == invalid.0 {
                    invalid.clone()
                } else {
                    entry
                }
            });
            assert!(matches!(
                DynamicLayer::from_named(Arc::clone(&schema), values),
                Err(FieldError::Constraint { .. })
            ));
        }

        assert!(matches!(
            FieldSchema::new(
                FieldId::from_static("bad"),
                "bad",
                std::iter::empty::<&str>(),
                FieldKind::Text,
                false,
                false,
                "bad limit",
                FieldConstraints {
                    text_bytes: Some(LengthRange::new(5, 4)),
                    ..FieldConstraints::default()
                },
            ),
            Err(SchemaError::InvalidLengthConstraint { .. })
        ));
    }

    #[test]
    fn only_derived_fields_admit_the_automatic_sentinel() {
        let derived = FieldSchema::new(
            FieldId::from_static("derived"),
            "derived",
            std::iter::empty::<&str>(),
            FieldKind::Unsigned,
            true,
            true,
            "Derived number",
            FieldConstraints::unsigned(0, 10),
        )
        .unwrap();
        let fixed = field(
            "fixed",
            "fixed",
            [],
            FieldKind::Unsigned,
            true,
            FieldConstraints::unsigned(0, 10),
        );
        let schema = schema([derived, fixed]);

        DynamicLayer::from_named(
            Arc::clone(&schema),
            [
                ("derived", FieldValue::Text("AUTO".to_owned())),
                ("fixed", FieldValue::Unsigned(1)),
            ],
        )
        .unwrap();
        assert!(matches!(
            DynamicLayer::from_named(
                schema,
                [
                    ("derived", FieldValue::Text("manual".to_owned())),
                    ("fixed", FieldValue::Unsigned(1)),
                ],
            ),
            Err(FieldError::WrongKind { .. })
        ));
    }

    #[test]
    fn updates_use_stable_slots_and_preserve_schema_identity_and_order() {
        let schema = schema([
            field(
                "first",
                "first",
                ["one"],
                FieldKind::Unsigned,
                true,
                FieldConstraints::unsigned(0, 10),
            ),
            field(
                "second",
                "second",
                ["two"],
                FieldKind::Text,
                true,
                FieldConstraints::text_bytes(1, 8),
            ),
        ]);
        let mut layer = DynamicLayer::from_named(
            Arc::clone(&schema),
            [
                ("two", FieldValue::Text("value".to_owned())),
                ("one", FieldValue::Unsigned(1)),
            ],
        )
        .unwrap();
        let schema_hash = layer.schema().schema_hash.clone();
        layer
            .set_field_by_id(&FieldId::from_static("first"), FieldValue::Unsigned(2))
            .unwrap();
        layer
            .set_field("second", FieldValue::Text("next".to_owned()))
            .unwrap();

        assert_eq!(layer.schema().schema_hash, schema_hash);
        assert_eq!(layer.protocol_id(), &schema.protocol);
        assert_eq!(
            layer
                .schema()
                .fields
                .iter()
                .map(|field| field.id.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(matches!(
            layer.set_field("one", FieldValue::Unsigned(11)),
            Err(FieldError::Constraint { .. })
        ));
        assert!(matches!(
            layer.set_field("unknown", FieldValue::Unsigned(1)),
            Err(FieldError::UnknownField { .. })
        ));
        assert_eq!(layer.clone_box().schema().schema_hash, schema_hash);
    }
}
