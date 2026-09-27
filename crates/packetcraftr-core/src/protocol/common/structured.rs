// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::field::{self, FieldKind, FieldValue};
use crate::layer::{FieldSchema, ReflectiveField, Schema};
use std::collections::BTreeMap;

pub(crate) const fn member(
    name: &'static str,
    kind: FieldKind,
    children: &'static [FieldSchema],
) -> FieldSchema {
    FieldSchema {
        name,
        aliases: &[],
        kind,
        derived: false,
        required: false,
        description: name,
        children,
    }
}

pub(crate) fn object<const N: usize>(fields: [(&str, FieldValue); N]) -> FieldValue {
    FieldValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

pub(crate) struct Object {
    values: BTreeMap<String, FieldValue>,
    schema: &'static Schema,
    field: String,
}

impl Object {
    pub(crate) fn contains(&self, name: &str) -> bool {
        self.values.contains_key(name)
    }
    pub(crate) fn new(
        value: FieldValue,
        schema: &'static Schema,
        field: &str,
    ) -> Result<Self, field::Error> {
        let FieldValue::Object(values) = value else {
            return Err(super::wrong_type(schema, field, "object"));
        };
        if values.len() > 256 {
            return Err(super::out_of_range(schema, field));
        }
        Ok(Self {
            values,
            schema,
            field: field.to_owned(),
        })
    }
    pub(crate) fn take(&mut self, name: &str) -> Option<FieldValue> {
        self.values.remove(name)
    }
    pub(crate) fn required(&mut self, name: &str) -> Result<FieldValue, field::Error> {
        self.take(name)
            .ok_or_else(|| field::Error::MissingRequired {
                protocol: self.schema.protocol,
                field: format!("{}.{}", self.field, name),
            })
    }
    pub(crate) fn required_with<T: ReflectiveField>(
        &mut self,
        name: &str,
        mut initial: T,
    ) -> Result<T, field::Error> {
        let value = self.required(name)?;
        crate::layer::reflect_set(
            &mut initial,
            self.schema,
            &format!("{}.{}", self.field, name),
            value,
        )?;
        Ok(initial)
    }
    pub(crate) fn required_value<T: ReflectiveField + Default>(
        &mut self,
        name: &str,
    ) -> Result<T, field::Error> {
        let value = self.required(name)?;
        let mut result = T::default();
        crate::layer::reflect_set(
            &mut result,
            self.schema,
            &format!("{}.{}", self.field, name),
            value,
        )?;
        Ok(result)
    }
    pub(crate) fn value<T: ReflectiveField>(
        &mut self,
        name: &str,
        default: T,
    ) -> Result<T, field::Error> {
        let mut result = default;
        if let Some(value) = self.take(name) {
            crate::layer::reflect_set(
                &mut result,
                self.schema,
                &format!("{}.{}", self.field, name),
                value,
            )?;
        }
        Ok(result)
    }
    pub(crate) fn finish(self) -> Result<(), field::Error> {
        if let Some((name, _)) = self.values.first_key_value() {
            Err(field::Error::UnknownField {
                protocol: self.schema.protocol,
                field: format!("{}.{}", self.field, name),
            })
        } else {
            Ok(())
        }
    }
}

pub(crate) fn list(
    value: FieldValue,
    maximum: usize,
    schema: &'static Schema,
    field: &str,
) -> Result<Vec<FieldValue>, field::Error> {
    match value {
        FieldValue::List(values) if values.len() <= maximum => Ok(values),
        FieldValue::List(_) => Err(super::out_of_range(schema, field)),
        _ => Err(super::wrong_type(schema, field, "list")),
    }
}

pub(crate) struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
    protocol: &'static str,
}

impl Encoder {
    pub(crate) fn new(protocol: &'static str, maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            protocol,
        }
    }
    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> Result<(), crate::codec::Error> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| {
                super::invalid(
                    self.protocol,
                    format!("encoded message exceeds {} bytes", self.maximum),
                )
            })?;
        self.bytes
            .try_reserve(length - self.bytes.len())
            .map_err(|_| super::invalid(self.protocol, "message allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn u8(&mut self, value: u8) -> Result<(), crate::codec::Error> {
        self.bytes(&[value])
    }
    pub(crate) fn u16(&mut self, value: u16) -> Result<(), crate::codec::Error> {
        self.bytes(&value.to_be_bytes())
    }
    pub(crate) fn u32(&mut self, value: u32) -> Result<(), crate::codec::Error> {
        self.bytes(&value.to_be_bytes())
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}
