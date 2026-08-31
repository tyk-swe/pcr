// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Retention of a `value` that arrived before its `type`.

use bytes::Bytes;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Unexpected, Visitor};

use std::fmt;

use crate::document::types::Limit;
use crate::field::FieldValue;

use super::budget::{BOOL_PAYLOAD_BYTES, Budget, INTEGER_PAYLOAD_BYTES, IPV6_PAYLOAD_BYTES};
use super::seed::{BoundedString, FieldValueSeed, Tag};

/// A `value` that arrived before its `type`.
///
/// The value is retained under the most expensive interpretation it could
/// still have: strings are text, and sequence elements are charged as list
/// items, nodes, and payload bytes at once. A document that puts `value`
/// first therefore fits a slightly narrower envelope than the same document
/// with `type` first, but never a wider one.
pub(super) enum Buffered {
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Text(String),
    Seq(Vec<BufferedItem>),
}

pub(super) enum BufferedItem {
    Unsigned(u64),
    Signed(i64),
    Value(FieldValue),
}

impl Buffered {
    pub(super) fn into_value<E: de::Error>(
        self,
        tag: Tag,
        budget: &Budget<'_>,
    ) -> Result<FieldValue, E> {
        match (tag, self) {
            (Tag::Bool, Self::Bool(value)) => Ok(FieldValue::Bool(value)),
            (Tag::Unsigned, Self::Unsigned(value)) => Ok(FieldValue::Unsigned(value)),
            (Tag::Signed, Self::Signed(value)) => Ok(FieldValue::Signed(value)),
            (Tag::Signed, Self::Unsigned(value)) => i64::try_from(value)
                .map(FieldValue::Signed)
                .map_err(|_| E::invalid_value(Unexpected::Unsigned(value), &"a signed integer")),
            (Tag::Text, Self::Text(value)) => Ok(FieldValue::Text(value)),
            (Tag::Ipv4, Self::Text(value)) => value
                .parse()
                .map(FieldValue::Ipv4)
                .map_err(|_| E::invalid_value(Unexpected::Str(&value), &"an IPv4 address")),
            (Tag::Ipv6, Self::Text(value)) => {
                // The buffered string has already been charged by its text
                // length. A compressed address can be shorter than the
                // retained 16-byte value, so reserve the difference now.
                budget.charge_payload(IPV6_PAYLOAD_BYTES.saturating_sub(value.len()))?;
                value
                    .parse()
                    .map(FieldValue::Ipv6)
                    .map_err(|_| E::invalid_value(Unexpected::Str(&value), &"an IPv6 address"))
            }
            (Tag::Bytes, Self::Seq(items)) => {
                budget.check_width(items.len(), Limit::ByteValueBytes)?;
                items
                    .into_iter()
                    .map(BufferedItem::into_byte)
                    .collect::<Result<Vec<u8>, E>>()
                    .map(|bytes| FieldValue::Bytes(Bytes::from(bytes)))
            }
            (Tag::Mac, Self::Seq(items)) => {
                let bytes = items
                    .into_iter()
                    .map(BufferedItem::into_byte)
                    .collect::<Result<Vec<u8>, E>>()?;
                <[u8; 6]>::try_from(bytes)
                    .map(FieldValue::Mac)
                    .map_err(|bytes| E::invalid_length(bytes.len(), &"6 MAC address bytes"))
            }
            (Tag::List, Self::Seq(items)) => items
                .into_iter()
                .map(|item| match item {
                    BufferedItem::Value(value) => Ok(value),
                    BufferedItem::Unsigned(value) => Err(E::invalid_type(
                        Unexpected::Unsigned(value),
                        &"a tagged field value object",
                    )),
                    BufferedItem::Signed(value) => Err(E::invalid_type(
                        Unexpected::Signed(value),
                        &"a tagged field value object",
                    )),
                })
                .collect::<Result<Vec<_>, E>>()
                .map(FieldValue::List),
            (tag, other) => Err(E::invalid_type(other.unexpected(), &tag.expected())),
        }
    }

    fn unexpected(&self) -> Unexpected<'_> {
        match self {
            Self::Bool(value) => Unexpected::Bool(*value),
            Self::Unsigned(value) => Unexpected::Unsigned(*value),
            Self::Signed(value) => Unexpected::Signed(*value),
            Self::Text(value) => Unexpected::Str(value),
            Self::Seq(_) => Unexpected::Seq,
        }
    }
}

impl BufferedItem {
    fn into_byte<E: de::Error>(self) -> Result<u8, E> {
        match self {
            Self::Unsigned(value) => u8::try_from(value)
                .map_err(|_| E::invalid_value(Unexpected::Unsigned(value), &"a byte")),
            Self::Signed(value) => Err(E::invalid_value(Unexpected::Signed(value), &"a byte")),
            Self::Value(_) => Err(E::invalid_type(Unexpected::Map, &"a byte")),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct BufferedSeed<'b, 'l> {
    pub(super) budget: &'b Budget<'l>,
    pub(super) depth: usize,
}

impl<'de> DeserializeSeed<'de> for BufferedSeed<'_, '_> {
    type Value = Buffered;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for BufferedSeed<'_, '_> {
    type Value = Buffered;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a boolean, integer, string, or array field value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        self.budget.charge_payload(BOOL_PAYLOAD_BYTES)?;
        Ok(Buffered::Bool(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        self.budget.charge_payload(INTEGER_PAYLOAD_BYTES)?;
        Ok(Buffered::Unsigned(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        self.budget.charge_payload(INTEGER_PAYLOAD_BYTES)?;
        u64::try_from(value).map_or(Ok(Buffered::Signed(value)), |value| {
            Ok(Buffered::Unsigned(value))
        })
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        BoundedString {
            budget: self.budget,
            limit: Limit::TextBytes,
        }
        .visit_str(value)
        .map(Buffered::Text)
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        BoundedString {
            budget: self.budget,
            limit: Limit::TextBytes,
        }
        .visit_string(value)
        .map(Buffered::Text)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.budget.enter_list(self.depth)?;
        if let Some(hint) = sequence.size_hint() {
            self.budget.check_width(hint, Limit::ListItems)?;
        }
        let mut items = Vec::with_capacity(
            self.budget
                .bounded_capacity(sequence.size_hint(), Limit::ListItems),
        );
        loop {
            if let Some(limit) = self.budget.list_budget_full(items.len()) {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(self.budget.exceeded(limit));
                }
                return Ok(Buffered::Seq(items));
            }
            self.budget.charge_list_item()?;
            let Some(item) = sequence.next_element_seed(BufferedItemSeed {
                budget: self.budget,
                depth: self.depth.saturating_add(1),
            })?
            else {
                self.budget.refund_list_item();
                return Ok(Buffered::Seq(items));
            };
            items.push(item);
        }
    }
}

#[derive(Clone, Copy)]
struct BufferedItemSeed<'b, 'l> {
    budget: &'b Budget<'l>,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BufferedItemSeed<'_, '_> {
    type Value = BufferedItem;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for BufferedItemSeed<'_, '_> {
    type Value = BufferedItem;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a byte or a tagged field value object")
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        self.budget.charge_node()?;
        self.budget.charge_payload(1)?;
        Ok(BufferedItem::Unsigned(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        self.budget.charge_node()?;
        self.budget.charge_payload(1)?;
        u64::try_from(value).map_or(Ok(BufferedItem::Signed(value)), |value| {
            Ok(BufferedItem::Unsigned(value))
        })
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let seed = FieldValueSeed {
            budget: self.budget,
            depth: self.depth,
        };
        seed.budget.charge_node()?;
        seed.visit_map(map).map(BufferedItem::Value)
    }
}
