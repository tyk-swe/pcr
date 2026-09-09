// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tag-independent, bounded staging. Numbers in arrays occupy one byte;
//! only tagged objects consume semantic list items and nodes.

use std::fmt;

use bytes::Bytes;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Unexpected, Visitor};

use crate::document::types::Limit;
use crate::field::FieldValue;

use super::budget::{
    BOOL_PAYLOAD_BYTES, Budget, INTEGER_PAYLOAD_BYTES, IPV4_PAYLOAD_BYTES, IPV6_PAYLOAD_BYTES,
    MAC_PAYLOAD_BYTES,
};
use super::seed::{FieldValueSeed, Tag};

pub(super) enum Buffered {
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Text(String),
    Empty,
    Bytes(Vec<u8>),
    List(Vec<FieldValue>),
}

impl Buffered {
    pub(super) fn into_value<E: de::Error>(
        self,
        tag: Tag,
        budget: &Budget<'_>,
        depth: usize,
    ) -> Result<FieldValue, E> {
        let value = match (tag, self) {
            (Tag::Bool, Self::Bool(value)) => FieldValue::Bool(value),
            (Tag::Unsigned, Self::Unsigned(value)) => FieldValue::Unsigned(value),
            (Tag::Signed, Self::Signed(value)) => FieldValue::Signed(value),
            (Tag::Signed, Self::Unsigned(value)) => {
                FieldValue::Signed(i64::try_from(value).map_err(|_| {
                    E::invalid_value(Unexpected::Unsigned(value), &"a signed integer")
                })?)
            }
            (Tag::Text, Self::Text(value)) => {
                budget.check_width(value.len(), Limit::TextBytes)?;
                FieldValue::Text(value)
            }
            (Tag::Ipv4, Self::Text(value)) => FieldValue::Ipv4(
                value
                    .parse()
                    .map_err(|_| E::invalid_value(Unexpected::Str(&value), &"an IPv4 address"))?,
            ),
            (Tag::Ipv6, Self::Text(value)) => FieldValue::Ipv6(
                value
                    .parse()
                    .map_err(|_| E::invalid_value(Unexpected::Str(&value), &"an IPv6 address"))?,
            ),
            (Tag::Bytes, Self::Bytes(value)) => {
                budget.check_width(value.len(), Limit::ByteValueBytes)?;
                FieldValue::Bytes(Bytes::from(value))
            }
            (Tag::Bytes, Self::Empty) => FieldValue::Bytes(Bytes::new()),
            (Tag::Mac, Self::Bytes(value)) => {
                FieldValue::Mac(value.try_into().map_err(|value: Vec<u8>| {
                    E::invalid_length(value.len(), &"6 MAC address bytes")
                })?)
            }
            (Tag::List, Self::List(value)) => {
                budget.enter_list(depth)?;
                FieldValue::List(value)
            }
            (Tag::List, Self::Empty) => {
                budget.enter_list(depth)?;
                FieldValue::List(Vec::new())
            }
            (tag, other) => return Err(E::invalid_type(other.unexpected(), &tag.expected())),
        };
        let width = match &value {
            FieldValue::Bool(_) => BOOL_PAYLOAD_BYTES,
            FieldValue::Unsigned(_) | FieldValue::Signed(_) => INTEGER_PAYLOAD_BYTES,
            FieldValue::Text(value) => value.len(),
            FieldValue::Bytes(value) => value.len(),
            FieldValue::Ipv4(_) => IPV4_PAYLOAD_BYTES,
            FieldValue::Ipv6(_) => IPV6_PAYLOAD_BYTES,
            FieldValue::Mac(_) => MAC_PAYLOAD_BYTES,
            // Children were charged when their tags were resolved.
            FieldValue::List(_) => 0,
        };
        budget.charge_payload(width)?;
        Ok(value)
    }

    fn unexpected(&self) -> Unexpected<'_> {
        match self {
            Self::Bool(value) => Unexpected::Bool(*value),
            Self::Unsigned(value) => Unexpected::Unsigned(*value),
            Self::Signed(value) => Unexpected::Signed(*value),
            Self::Text(value) => Unexpected::Str(value),
            Self::Empty | Self::Bytes(_) | Self::List(_) => Unexpected::Seq,
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
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Buffered, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for BufferedSeed<'_, '_> {
    type Value = Buffered;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a boolean, integer, string, or array field value")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Buffered, E> {
        Ok(Buffered::Bool(value))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Buffered, E> {
        Ok(Buffered::Unsigned(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Buffered, E> {
        Ok(u64::try_from(value).map_or(Buffered::Signed(value), Buffered::Unsigned))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Buffered, E> {
        // The only possible string tags are text, IPv4 and IPv6. Even an
        // uncompressed IPv6 address with a dotted IPv4 tail is at most 45
        // bytes. Reject impossible candidates before copying their text.
        if value.len() > self.budget.limits.max_text_bytes.max(45) {
            return Err(self.budget.exceeded(Limit::TextBytes));
        }
        self.budget.charge_temporary(value.len())?;
        Ok(Buffered::Text(value.to_owned()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Buffered, E> {
        if value.len() > self.budget.limits.max_text_bytes.max(45) {
            return Err(self.budget.exceeded(Limit::TextBytes));
        }
        self.budget.charge_temporary(value.capacity())?;
        Ok(Buffered::Text(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Buffered, A::Error> {
        let mut result = Buffered::Empty;
        let mut count = 0usize;
        while let Some(item) = sequence.next_element_seed(ItemSeed {
            parent: self,
            count,
        })? {
            if count == 0 {
                self.budget
                    .charge_temporary(std::mem::size_of::<FieldValue>())?;
            }
            match (&mut result, item) {
                (Buffered::Empty, Item::Byte(value)) => result = Buffered::Bytes(vec![value]),
                (Buffered::Empty, Item::Value(value)) => result = Buffered::List(vec![value]),
                (Buffered::Bytes(values), Item::Byte(value)) => {
                    grow(values, self.budget)?;
                    values.push(value);
                }
                (Buffered::List(values), Item::Value(value)) => {
                    grow(values, self.budget)?;
                    values.push(value);
                }
                _ => {
                    return Err(de::Error::custom(
                        "mixed bytes and tagged values in an array",
                    ));
                }
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| self.budget.exceeded(Limit::InputBytes))?;
        }
        Ok(result)
    }
}

fn grow<T, E: de::Error>(values: &mut Vec<T>, budget: &Budget<'_>) -> Result<(), E> {
    if values.len() == values.capacity() {
        let extra = values.capacity().max(1);
        let bytes = extra
            .checked_mul(std::mem::size_of::<T>())
            .ok_or_else(|| budget.exceeded(Limit::InputBytes))?;
        budget.charge_temporary(bytes)?;
        values.try_reserve_exact(extra).map_err(E::custom)?;
    }
    Ok(())
}

enum Item {
    Byte(u8),
    Value(FieldValue),
}
struct ItemSeed<'b, 'l> {
    parent: BufferedSeed<'b, 'l>,
    count: usize,
}
impl<'de> DeserializeSeed<'de> for ItemSeed<'_, '_> {
    type Value = Item;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Item, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ItemSeed<'_, '_> {
    type Value = Item;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte or a tagged field value object")
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Item, E> {
        let byte = u8::try_from(value)
            .map_err(|_| E::invalid_value(Unexpected::Unsigned(value), &"a byte"))?;
        // Until the tag arrives the array can be bytes or a six-byte MAC.
        if self.count
            >= self
                .parent
                .budget
                .limits
                .max_byte_value_bytes
                .max(MAC_PAYLOAD_BYTES)
        {
            return Err(self.parent.budget.exceeded(Limit::ByteValueBytes));
        }
        Ok(Item::Byte(byte))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Item, E> {
        let value = u64::try_from(value)
            .map_err(|_| E::invalid_value(Unexpected::Signed(value), &"a byte"))?;
        self.visit_u64(value)
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Item, A::Error> {
        let budget = self.parent.budget;
        budget.enter_list(self.parent.depth)?;
        if let Some(limit) = budget.list_budget_full(self.count) {
            return Err(budget.exceeded(limit));
        }
        budget.charge_list_item()?;
        budget.charge_node()?;
        FieldValueSeed {
            budget,
            depth: self.parent.depth + 1,
        }
        .visit_map(map)
        .map(Item::Value)
    }
}
