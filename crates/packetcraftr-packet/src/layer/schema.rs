// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned immutable layer schemas and validated construction fields.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use packetcraftr_model::{ContentDigest, FieldId, IdentityError, ProtocolId};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::field::{FieldKind, FieldValue};

pub const MAX_SCHEMA_FIELDS: usize = 1_024;
pub const MAX_SCHEMA_ALIASES: usize = 64;
pub const MAX_SCHEMA_DISPLAY_NAME_BYTES: usize = 256;
pub const MAX_FIELD_DESCRIPTION_BYTES: usize = 4_096;
pub const MAX_CONSTRAINED_VALUE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CONSTRAINED_LIST_ITEMS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct UnsignedRange {
    pub minimum: u64,
    pub maximum: u64,
}

impl UnsignedRange {
    pub const fn new(minimum: u64, maximum: u64) -> Self {
        Self { minimum, maximum }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SignedRange {
    pub minimum: i64,
    pub maximum: i64,
}

impl SignedRange {
    pub const fn new(minimum: i64, maximum: i64) -> Self {
        Self { minimum, maximum }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LengthRange {
    pub minimum: usize,
    pub maximum: usize,
}

impl LengthRange {
    pub const fn new(minimum: usize, maximum: usize) -> Self {
        Self { minimum, maximum }
    }

    fn contains(self, length: usize) -> bool {
        (self.minimum..=self.maximum).contains(&length)
    }
}

/// Deliberately small constraints needed by packet fields and guest results.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FieldConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<UnsignedRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_bytes: Option<LengthRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<LengthRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_length: Option<LengthRange>,
}

impl FieldConstraints {
    pub const fn unsigned(minimum: u64, maximum: u64) -> Self {
        Self {
            unsigned: Some(UnsignedRange::new(minimum, maximum)),
            signed: None,
            text_bytes: None,
            byte_length: None,
            list_length: None,
        }
    }

    pub const fn signed(minimum: i64, maximum: i64) -> Self {
        Self {
            unsigned: None,
            signed: Some(SignedRange::new(minimum, maximum)),
            text_bytes: None,
            byte_length: None,
            list_length: None,
        }
    }

    pub const fn text_bytes(minimum: usize, maximum: usize) -> Self {
        Self {
            unsigned: None,
            signed: None,
            text_bytes: Some(LengthRange::new(minimum, maximum)),
            byte_length: None,
            list_length: None,
        }
    }

    pub const fn byte_length(minimum: usize, maximum: usize) -> Self {
        Self {
            unsigned: None,
            signed: None,
            text_bytes: None,
            byte_length: Some(LengthRange::new(minimum, maximum)),
            list_length: None,
        }
    }

    pub const fn list_length(minimum: usize, maximum: usize) -> Self {
        Self {
            unsigned: None,
            signed: None,
            text_bytes: None,
            byte_length: None,
            list_length: Some(LengthRange::new(minimum, maximum)),
        }
    }

    fn validate_for(self, kind: FieldKind) -> Result<(), SchemaError> {
        let populated = usize::from(self.unsigned.is_some())
            + usize::from(self.signed.is_some())
            + usize::from(self.text_bytes.is_some())
            + usize::from(self.byte_length.is_some())
            + usize::from(self.list_length.is_some());
        if populated != 0
            && (populated > 1
                || self.unsigned.is_some() != (populated == 1 && kind == FieldKind::Unsigned)
                || self.signed.is_some() != (populated == 1 && kind == FieldKind::Signed)
                || self.text_bytes.is_some() != (populated == 1 && kind == FieldKind::Text)
                || self.byte_length.is_some() != (populated == 1 && kind == FieldKind::Bytes)
                || self.list_length.is_some() != (populated == 1 && kind == FieldKind::List))
        {
            return Err(SchemaError::ConstraintKind { kind });
        }
        if self
            .unsigned
            .is_some_and(|range| range.minimum > range.maximum)
            || self
                .signed
                .is_some_and(|range| range.minimum > range.maximum)
        {
            return Err(SchemaError::InvalidConstraintRange);
        }
        for range in [self.text_bytes, self.byte_length].into_iter().flatten() {
            if range.minimum > range.maximum || range.maximum > MAX_CONSTRAINED_VALUE_BYTES {
                return Err(SchemaError::InvalidLengthConstraint {
                    maximum: range.maximum,
                    limit: MAX_CONSTRAINED_VALUE_BYTES,
                });
            }
        }
        if let Some(range) = self.list_length
            && (range.minimum > range.maximum || range.maximum > MAX_CONSTRAINED_LIST_ITEMS)
        {
            return Err(SchemaError::InvalidLengthConstraint {
                maximum: range.maximum,
                limit: MAX_CONSTRAINED_LIST_ITEMS,
            });
        }
        Ok(())
    }

    pub fn accepts(self, value: &FieldValue) -> bool {
        match value {
            FieldValue::Unsigned(value) => self
                .unsigned
                .is_none_or(|range| (range.minimum..=range.maximum).contains(value)),
            FieldValue::Signed(value) => self
                .signed
                .is_none_or(|range| (range.minimum..=range.maximum).contains(value)),
            FieldValue::Text(value) => self
                .text_bytes
                .is_none_or(|range| range.contains(value.len())),
            FieldValue::Bytes(value) => self
                .byte_length
                .is_none_or(|range| range.contains(value.len())),
            FieldValue::List(value) => self
                .list_length
                .is_none_or(|range| range.contains(value.len())),
            FieldValue::Bool(_)
            | FieldValue::Ipv4(_)
            | FieldValue::Ipv6(_)
            | FieldValue::Mac(_) => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldSchema {
    pub id: FieldId,
    pub name: Arc<str>,
    pub aliases: Arc<[Arc<str>]>,
    pub kind: FieldKind,
    pub required: bool,
    pub derived: bool,
    pub description: Arc<str>,
    pub constraints: FieldConstraints,
}

impl FieldSchema {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FieldId,
        name: impl AsRef<str>,
        aliases: impl IntoIterator<Item = impl AsRef<str>>,
        kind: FieldKind,
        required: bool,
        derived: bool,
        description: impl AsRef<str>,
        constraints: FieldConstraints,
    ) -> Result<Self, SchemaError> {
        let name = normalize_field_name(name.as_ref())?;
        let aliases = normalize_aliases(aliases, &name)?;
        let description = description.as_ref();
        if description.len() > MAX_FIELD_DESCRIPTION_BYTES {
            return Err(SchemaError::DescriptionTooLong {
                actual: description.len(),
                limit: MAX_FIELD_DESCRIPTION_BYTES,
            });
        }
        constraints.validate_for(kind)?;
        Ok(Self {
            id,
            name,
            aliases,
            kind,
            required,
            derived,
            description: Arc::from(description),
            constraints,
        })
    }

    /// Returns whether `value` has a representation admitted by this field.
    ///
    /// Derived fields deliberately admit the stable textual `auto` sentinel
    /// in addition to their materialized kind. Native codecs resolve that
    /// sentinel during construction or encoding.
    pub fn accepts_kind(&self, value: &FieldValue) -> bool {
        self.kind == value.kind() || self.is_automatic(value)
    }

    pub fn accepts(&self, value: &FieldValue) -> bool {
        self.is_automatic(value) || (self.kind == value.kind() && self.constraints.accepts(value))
    }

    fn is_automatic(&self, value: &FieldValue) -> bool {
        self.derived
            && matches!(value, FieldValue::Text(value) if value.eq_ignore_ascii_case("auto"))
    }

    fn validated(mut self) -> Result<Self, SchemaError> {
        self.name = normalize_field_name(&self.name)?;
        self.aliases = normalize_aliases(self.aliases.iter().map(AsRef::as_ref), &self.name)?;
        if self.description.len() > MAX_FIELD_DESCRIPTION_BYTES {
            return Err(SchemaError::DescriptionTooLong {
                actual: self.description.len(),
                limit: MAX_FIELD_DESCRIPTION_BYTES,
            });
        }
        self.constraints.validate_for(self.kind)?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LayerSchema {
    pub protocol: ProtocolId,
    pub display_name: Arc<str>,
    pub aliases: Arc<[Arc<str>]>,
    pub fields: Arc<[FieldSchema]>,
    pub version: u32,
    pub schema_hash: ContentDigest,
    #[serde(skip)]
    id_slots: BTreeMap<FieldId, usize>,
    #[serde(skip)]
    name_slots: BTreeMap<Arc<str>, usize>,
}

impl PartialEq for LayerSchema {
    fn eq(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.display_name == other.display_name
            && self.aliases == other.aliases
            && self.fields == other.fields
            && self.version == other.version
            && self.schema_hash == other.schema_hash
    }
}

impl Eq for LayerSchema {}

impl LayerSchema {
    pub fn new(
        protocol: ProtocolId,
        display_name: impl AsRef<str>,
        aliases: impl IntoIterator<Item = impl AsRef<str>>,
        version: u32,
        fields: impl IntoIterator<Item = FieldSchema>,
    ) -> Result<Self, SchemaError> {
        let display_name = display_name.as_ref();
        if display_name.trim().is_empty() {
            return Err(SchemaError::EmptyDisplayName);
        }
        if display_name.len() > MAX_SCHEMA_DISPLAY_NAME_BYTES {
            return Err(SchemaError::DisplayNameTooLong {
                actual: display_name.len(),
                limit: MAX_SCHEMA_DISPLAY_NAME_BYTES,
            });
        }
        let aliases = normalize_protocol_aliases(aliases, &protocol)?;
        let fields = fields
            .into_iter()
            .map(FieldSchema::validated)
            .collect::<Result<Vec<_>, _>>()?;
        if fields.len() > MAX_SCHEMA_FIELDS {
            return Err(SchemaError::TooManyFields {
                actual: fields.len(),
                limit: MAX_SCHEMA_FIELDS,
            });
        }
        let mut id_slots = BTreeMap::new();
        let mut name_slots = BTreeMap::new();
        for (slot, field) in fields.iter().enumerate() {
            if id_slots.insert(field.id.clone(), slot).is_some() {
                return Err(SchemaError::DuplicateFieldId {
                    field: field.id.clone(),
                });
            }
            for name in std::iter::once(&field.name).chain(field.aliases.iter()) {
                if let Some(previous) = name_slots.insert(Arc::clone(name), slot) {
                    return Err(SchemaError::DuplicateFieldName {
                        name: name.to_string(),
                        first: fields[previous].id.clone(),
                        second: field.id.clone(),
                    });
                }
            }
        }
        let display_name: Arc<str> = Arc::from(display_name);
        let aliases: Arc<[Arc<str>]> = aliases.into();
        let fields: Arc<[FieldSchema]> = fields.into();
        let schema_hash = hash_schema(&protocol, &display_name, &aliases, version, fields.as_ref());
        Ok(Self {
            protocol,
            display_name,
            aliases,
            fields,
            version,
            schema_hash,
            id_slots,
            name_slots,
        })
    }

    pub fn empty(
        protocol: ProtocolId,
        display_name: impl AsRef<str>,
        aliases: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, SchemaError> {
        Self::new(protocol, display_name, aliases, 1, [])
    }

    pub fn field(&self, id: &FieldId) -> Option<&FieldSchema> {
        self.field_slot(id).and_then(|slot| self.fields.get(slot))
    }

    pub fn field_slot(&self, id: &FieldId) -> Option<usize> {
        self.id_slots.get(id).copied()
    }

    pub fn field_named(&self, name: &str) -> Option<&FieldSchema> {
        self.field_slot_named(name)
            .and_then(|slot| self.fields.get(slot))
    }

    pub fn field_slot_named(&self, name: &str) -> Option<usize> {
        let normalized = normalize_field_name(name).ok()?;
        self.name_slots.get(normalized.as_ref()).copied()
    }

    pub fn canonical_field_id(&self, name: &str) -> Option<&FieldId> {
        self.field_named(name).map(|field| &field.id)
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedFieldSet {
    schema: Arc<LayerSchema>,
    values: Vec<Option<FieldValue>>,
}

impl ValidatedFieldSet {
    pub fn from_ids(
        schema: Arc<LayerSchema>,
        fields: impl IntoIterator<Item = (FieldId, FieldValue)>,
    ) -> Result<Self, FieldSetError> {
        let mut values = vec![None; schema.fields.len()];
        for (id, value) in fields {
            let Some(slot) = schema.field_slot(&id) else {
                return Err(FieldSetError::UnknownFieldId {
                    protocol: schema.protocol.clone(),
                    field: id,
                });
            };
            insert_value(&schema, &mut values, slot, value)?;
        }
        Ok(Self { schema, values })
    }

    pub fn from_names(
        schema: Arc<LayerSchema>,
        fields: impl IntoIterator<Item = (impl AsRef<str>, FieldValue)>,
    ) -> Result<Self, FieldSetError> {
        let mut values = vec![None; schema.fields.len()];
        for (name, value) in fields {
            let name = name.as_ref();
            let Some(slot) = schema.field_slot_named(name) else {
                return Err(FieldSetError::UnknownField {
                    protocol: schema.protocol.clone(),
                    field: name.to_owned(),
                });
            };
            insert_value(&schema, &mut values, slot, value)?;
        }
        Ok(Self { schema, values })
    }

    pub fn schema(&self) -> &Arc<LayerSchema> {
        &self.schema
    }

    pub fn get(&self, id: &FieldId) -> Option<&FieldValue> {
        self.schema
            .field_slot(id)
            .and_then(|slot| self.values.get(slot))
            .and_then(Option::as_ref)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FieldSchema, &FieldValue)> {
        self.schema
            .fields
            .iter()
            .zip(&self.values)
            .filter_map(|(field, value)| value.as_ref().map(|value| (field, value)))
    }

    pub(crate) fn into_parts(self) -> (Arc<LayerSchema>, Vec<Option<FieldValue>>) {
        (self.schema, self.values)
    }
}

fn insert_value(
    schema: &LayerSchema,
    values: &mut [Option<FieldValue>],
    slot: usize,
    value: FieldValue,
) -> Result<(), FieldSetError> {
    let field = &schema.fields[slot];
    if values[slot].is_some() {
        return Err(FieldSetError::DuplicateField {
            protocol: schema.protocol.clone(),
            field: field.id.clone(),
        });
    }
    if !field.accepts_kind(&value) {
        return Err(FieldSetError::WrongKind {
            protocol: schema.protocol.clone(),
            field: field.id.clone(),
            expected: field.kind,
            actual: value.kind(),
        });
    }
    if !field.accepts(&value) {
        return Err(FieldSetError::Constraint {
            protocol: schema.protocol.clone(),
            field: field.id.clone(),
        });
    }
    values[slot] = Some(value);
    Ok(())
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("layer schema display name is empty")]
    EmptyDisplayName,
    #[error("layer schema display name has {actual} bytes, exceeding limit {limit}")]
    DisplayNameTooLong { actual: usize, limit: usize },
    #[error("field description has {actual} bytes, exceeding limit {limit}")]
    DescriptionTooLong { actual: usize, limit: usize },
    #[error("layer schema has {actual} fields, exceeding limit {limit}")]
    TooManyFields { actual: usize, limit: usize },
    #[error("layer schema has {actual} aliases, exceeding limit {limit}")]
    TooManyAliases { actual: usize, limit: usize },
    #[error("field {field} is declared more than once")]
    DuplicateFieldId { field: FieldId },
    #[error("field spelling {name:?} is shared by {first} and {second}")]
    DuplicateFieldName {
        name: String,
        first: FieldId,
        second: FieldId,
    },
    #[error("alias {alias:?} duplicates its canonical name")]
    AliasMatchesCanonical { alias: String },
    #[error("alias {alias:?} is declared more than once")]
    DuplicateAlias { alias: String },
    #[error("constraints are incompatible with field kind {kind:?}")]
    ConstraintKind { kind: FieldKind },
    #[error("constraint minimum exceeds maximum")]
    InvalidConstraintRange,
    #[error("length constraint maximum {maximum} exceeds limit {limit}")]
    InvalidLengthConstraint { maximum: usize, limit: usize },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldSetError {
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
    #[error("field {field} on layer {protocol} expected {expected:?}, got {actual:?}")]
    WrongKind {
        protocol: ProtocolId,
        field: FieldId,
        expected: FieldKind,
        actual: FieldKind,
    },
    #[error("field {field} on layer {protocol} violates its constraints")]
    Constraint {
        protocol: ProtocolId,
        field: FieldId,
    },
}

fn normalize_field_name(value: &str) -> Result<Arc<str>, SchemaError> {
    let normalized = value.trim().to_ascii_lowercase();
    FieldId::new(&normalized)?;
    Ok(Arc::from(normalized))
}

fn normalize_aliases(
    aliases: impl IntoIterator<Item = impl AsRef<str>>,
    canonical: &str,
) -> Result<Arc<[Arc<str>]>, SchemaError> {
    let mut normalized = BTreeSet::new();
    for alias in aliases {
        let alias = normalize_field_name(alias.as_ref())?;
        if alias.as_ref() == canonical {
            return Err(SchemaError::AliasMatchesCanonical {
                alias: alias.to_string(),
            });
        }
        if !normalized.insert(alias.clone()) {
            return Err(SchemaError::DuplicateAlias {
                alias: alias.to_string(),
            });
        }
    }
    if normalized.len() > MAX_SCHEMA_ALIASES {
        return Err(SchemaError::TooManyAliases {
            actual: normalized.len(),
            limit: MAX_SCHEMA_ALIASES,
        });
    }
    Ok(normalized.into_iter().collect::<Vec<_>>().into())
}

fn normalize_protocol_aliases(
    aliases: impl IntoIterator<Item = impl AsRef<str>>,
    canonical: &ProtocolId,
) -> Result<Vec<Arc<str>>, SchemaError> {
    let mut normalized = BTreeSet::new();
    let canonical = canonical.as_str().trim().to_ascii_lowercase();
    for alias in aliases {
        let value = alias.as_ref().trim().to_ascii_lowercase();
        let alias = ProtocolId::new(&value)?;
        if alias.as_str() == canonical {
            return Err(SchemaError::AliasMatchesCanonical { alias: value });
        }
        if !normalized.insert(Arc::<str>::from(value.clone())) {
            return Err(SchemaError::DuplicateAlias { alias: value });
        }
    }
    if normalized.len() > MAX_SCHEMA_ALIASES {
        return Err(SchemaError::TooManyAliases {
            actual: normalized.len(),
            limit: MAX_SCHEMA_ALIASES,
        });
    }
    Ok(normalized.into_iter().collect())
}

fn hash_schema(
    protocol: &ProtocolId,
    display_name: &str,
    aliases: &[Arc<str>],
    version: u32,
    fields: &[FieldSchema],
) -> ContentDigest {
    let mut hash = Sha256::new();
    hash.update(b"packetcraftr-layer-schema-v1");
    hash_text(&mut hash, protocol.as_str());
    hash_text(&mut hash, display_name);
    hash.update(version.to_be_bytes());
    hash_len(&mut hash, aliases.len());
    for alias in aliases {
        hash_text(&mut hash, alias);
    }
    hash_len(&mut hash, fields.len());
    for field in fields {
        hash_text(&mut hash, field.id.as_str());
        hash_text(&mut hash, &field.name);
        hash_len(&mut hash, field.aliases.len());
        for alias in field.aliases.iter() {
            hash_text(&mut hash, alias);
        }
        hash.update([field_kind_tag(field.kind)]);
        hash.update([u8::from(field.required), u8::from(field.derived)]);
        hash_text(&mut hash, &field.description);
        hash_constraints(&mut hash, field.constraints);
    }
    ContentDigest::from_sha256(hash.finalize().into())
}

fn hash_constraints(hash: &mut Sha256, constraints: FieldConstraints) {
    match constraints.unsigned {
        Some(range) => {
            hash.update([1]);
            hash.update(range.minimum.to_be_bytes());
            hash.update(range.maximum.to_be_bytes());
        }
        None => hash.update([0]),
    }
    match constraints.signed {
        Some(range) => {
            hash.update([1]);
            hash.update(range.minimum.to_be_bytes());
            hash.update(range.maximum.to_be_bytes());
        }
        None => hash.update([0]),
    }
    for range in [
        constraints.text_bytes,
        constraints.byte_length,
        constraints.list_length,
    ] {
        match range {
            Some(range) => {
                hash.update([1]);
                hash_len(hash, range.minimum);
                hash_len(hash, range.maximum);
            }
            None => hash.update([0]),
        }
    }
}

fn hash_text(hash: &mut Sha256, value: &str) {
    hash_len(hash, value.len());
    hash.update(value.as_bytes());
}

fn hash_len(hash: &mut Sha256, value: usize) {
    hash.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

const fn field_kind_tag(kind: FieldKind) -> u8 {
    match kind {
        FieldKind::Bool => 0,
        FieldKind::Unsigned => 1,
        FieldKind::Signed => 2,
        FieldKind::Text => 3,
        FieldKind::Bytes => 4,
        FieldKind::Ipv4 => 5,
        FieldKind::Ipv6 => 6,
        FieldKind::Mac => 7,
        FieldKind::List => 8,
    }
}
