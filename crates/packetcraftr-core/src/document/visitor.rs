// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Budgeted deserialization of packet documents.
//!
//! Every seed shares one [`Budget`]. Counts and byte widths are charged
//! against it before the bounded item is allocated, pushed, or inserted, and
//! the first breach records which [`Limit`] tripped so the parser can report
//! it as a classified error instead of a format message.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Unexpected, Visitor};

use super::types::{DocumentLimits, Layer, Limit, Packet};
use crate::field::FieldValue;

/// Retained width charged for fixed-size scalars, in payload bytes.
const BOOL_PAYLOAD_BYTES: usize = 1;
const INTEGER_PAYLOAD_BYTES: usize = 8;
const IPV4_PAYLOAD_BYTES: usize = 4;
const IPV6_PAYLOAD_BYTES: usize = 16;
const MAC_PAYLOAD_BYTES: usize = 6;

/// Shared parse budget. Cheap interior mutability is enough: serde drives
/// one document on one thread.
pub(super) struct Budget<'l> {
    limits: &'l DocumentLimits,
    nodes: Cell<usize>,
    list_items: Cell<usize>,
    payload_bytes: Cell<usize>,
    breach: Cell<Option<Limit>>,
}

impl<'l> Budget<'l> {
    pub(super) fn new(limits: &'l DocumentLimits) -> Self {
        Self {
            limits,
            nodes: Cell::new(0),
            list_items: Cell::new(0),
            payload_bytes: Cell::new(0),
            breach: Cell::new(None),
        }
    }

    /// The first limit this budget rejected, if any.
    pub(super) fn breach(&self) -> Option<Limit> {
        self.breach.get()
    }

    fn exceeded<E: de::Error>(&self, limit: Limit) -> E {
        if self.breach.get().is_none() {
            self.breach.set(Some(limit));
        }
        E::custom(format_args!(
            "packet document exceeds configured limit {limit}={}",
            self.limits.maximum(limit)
        ))
    }

    fn charge<E: de::Error>(
        &self,
        counter: &Cell<usize>,
        amount: usize,
        limit: Limit,
    ) -> Result<(), E> {
        let next = counter
            .get()
            .checked_add(amount)
            .filter(|next| *next <= self.limits.maximum(limit))
            .ok_or_else(|| self.exceeded(limit))?;
        counter.set(next);
        Ok(())
    }

    fn charge_node<E: de::Error>(&self) -> Result<(), E> {
        self.charge(&self.nodes, 1, Limit::TotalNodes)
    }

    /// Which list budget is already full before another item is read, so the
    /// caller can probe for the item without allocating it.
    fn list_budget_full(&self, in_list: usize) -> Option<Limit> {
        if in_list >= self.limits.max_list_items {
            Some(Limit::ListItems)
        } else if self.list_items.get() >= self.limits.max_total_list_items {
            Some(Limit::TotalListItems)
        } else {
            None
        }
    }

    /// Charges one aggregate list item ahead of reading it; a read that finds
    /// the end of the list hands the charge back.
    fn charge_list_item<E: de::Error>(&self) -> Result<(), E> {
        self.charge(&self.list_items, 1, Limit::TotalListItems)
    }

    fn refund_list_item(&self) {
        self.list_items.set(self.list_items.get().saturating_sub(1));
    }

    fn charge_payload<E: de::Error>(&self, bytes: usize) -> Result<(), E> {
        self.charge(&self.payload_bytes, bytes, Limit::TotalPayloadBytes)
    }

    fn check_width<E: de::Error>(&self, actual: usize, limit: Limit) -> Result<(), E> {
        if actual > self.limits.maximum(limit) {
            return Err(self.exceeded(limit));
        }
        Ok(())
    }

    /// Entering a list at `depth` enclosing lists.
    fn enter_list<E: de::Error>(&self, depth: usize) -> Result<(), E> {
        if depth >= self.limits.max_nesting {
            return Err(self.exceeded(Limit::Nesting));
        }
        Ok(())
    }

    /// Reserves capacity for a sequence without trusting its size hint beyond
    /// the remaining budget.
    fn bounded_capacity(&self, hint: Option<usize>, limit: Limit) -> usize {
        hint.unwrap_or(0).min(self.limits.maximum(limit))
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum PacketField {
    Schema,
    Layers,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum LayerField {
    Protocol,
    Fields,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum ValueField {
    Type,
    Value,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Tag {
    Bool,
    Unsigned,
    Signed,
    Text,
    Bytes,
    Ipv4,
    Ipv6,
    Mac,
    List,
}

#[derive(Clone, Copy)]
pub(super) struct PacketSeed<'b, 'l> {
    pub(super) budget: &'b Budget<'l>,
}

impl<'de> DeserializeSeed<'de> for PacketSeed<'_, '_> {
    type Value = Packet;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct("Packet", &["schema", "layers"], self)
    }
}

impl<'de> Visitor<'de> for PacketSeed<'_, '_> {
    type Value = Packet;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a packet document object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut schema = None;
        let mut layers = None;
        while let Some(field) = map.next_key::<PacketField>()? {
            match field {
                PacketField::Schema => {
                    if schema.is_some() {
                        return Err(de::Error::duplicate_field("schema"));
                    }
                    schema = Some(map.next_value_seed(SchemaString {
                        budget: self.budget,
                    })?);
                }
                PacketField::Layers => {
                    if layers.is_some() {
                        return Err(de::Error::duplicate_field("layers"));
                    }
                    layers = Some(map.next_value_seed(LayersSeed {
                        budget: self.budget,
                    })?);
                }
            }
        }
        Ok(Packet {
            schema: schema.ok_or_else(|| de::Error::missing_field("schema"))?,
            layers: layers.ok_or_else(|| de::Error::missing_field("layers"))?,
        })
    }
}

#[derive(Clone, Copy)]
struct LayersSeed<'b, 'l> {
    budget: &'b Budget<'l>,
}

impl<'de> DeserializeSeed<'de> for LayersSeed<'_, '_> {
    type Value = Vec<Layer>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for LayersSeed<'_, '_> {
    type Value = Vec<Layer>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {} packet layers",
            self.budget.limits.max_layers
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let maximum = self.budget.limits.max_layers;
        if let Some(hint) = sequence.size_hint() {
            self.budget.check_width(hint, Limit::Layers)?;
        }
        let mut layers = Vec::with_capacity(
            self.budget
                .bounded_capacity(sequence.size_hint(), Limit::Layers),
        );
        while layers.len() < maximum {
            let Some(layer) = sequence.next_element_seed(LayerSeed {
                budget: self.budget,
            })?
            else {
                return Ok(layers);
            };
            layers.push(layer);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(self.budget.exceeded(Limit::Layers));
        }
        Ok(layers)
    }
}

#[derive(Clone, Copy)]
struct LayerSeed<'b, 'l> {
    budget: &'b Budget<'l>,
}

impl<'de> DeserializeSeed<'de> for LayerSeed<'_, '_> {
    type Value = Layer;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct("Layer", &["protocol", "fields"], self)
    }
}

impl<'de> Visitor<'de> for LayerSeed<'_, '_> {
    type Value = Layer;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a packet layer object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut protocol = None;
        let mut fields = None;
        while let Some(field) = map.next_key::<LayerField>()? {
            match field {
                LayerField::Protocol => {
                    if protocol.is_some() {
                        return Err(de::Error::duplicate_field("protocol"));
                    }
                    protocol = Some(map.next_value_seed(BoundedString {
                        budget: self.budget,
                        limit: Limit::ProtocolNameBytes,
                    })?);
                }
                LayerField::Fields => {
                    if fields.is_some() {
                        return Err(de::Error::duplicate_field("fields"));
                    }
                    fields = Some(map.next_value_seed(FieldsSeed {
                        budget: self.budget,
                    })?);
                }
            }
        }
        Ok(Layer {
            protocol: protocol.ok_or_else(|| de::Error::missing_field("protocol"))?,
            fields: fields.unwrap_or_default(),
        })
    }
}

#[derive(Clone, Copy)]
struct FieldsSeed<'b, 'l> {
    budget: &'b Budget<'l>,
}

impl<'de> DeserializeSeed<'de> for FieldsSeed<'_, '_> {
    type Value = BTreeMap<String, FieldValue>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for FieldsSeed<'_, '_> {
    type Value = BTreeMap<String, FieldValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of unique reflective field names")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let maximum = self.budget.limits.max_fields_per_layer;
        let mut fields = BTreeMap::new();
        loop {
            if fields.len() >= maximum {
                // The layer is full: any further key is a breach, and probing
                // with `IgnoredAny` allocates nothing for it.
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(self.budget.exceeded(Limit::FieldsPerLayer));
                }
                return Ok(fields);
            }
            let Some(name) = map.next_key_seed(BoundedString {
                budget: self.budget,
                limit: Limit::FieldNameBytes,
            })?
            else {
                return Ok(fields);
            };
            if fields.contains_key(&name) {
                return Err(de::Error::custom(format_args!(
                    "duplicate reflective field {name:?}"
                )));
            }
            let value = map.next_value_seed(FieldValueSeed {
                budget: self.budget,
                depth: 0,
            })?;
            fields.insert(name, value);
        }
    }
}

/// The schema identifier is bounded by the configured text width, but does not
/// compete with field-value payload budgets.
struct SchemaString<'b, 'l> {
    budget: &'b Budget<'l>,
}

impl<'de> DeserializeSeed<'de> for SchemaString<'_, '_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for SchemaString<'_, '_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a schema identifier of at most {} bytes",
            self.budget.limits.max_text_bytes
        )
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.budget.check_width(value.len(), Limit::TextBytes)?;
        Ok(value.to_owned())
    }
}

/// A string whose byte length is checked before it is copied out of the
/// deserializer.
#[derive(Clone, Copy)]
struct BoundedString<'b, 'l> {
    budget: &'b Budget<'l>,
    limit: Limit,
}

impl<'de> DeserializeSeed<'de> for BoundedString<'_, '_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for BoundedString<'_, '_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a string of at most {} bytes",
            self.budget.limits.maximum(self.limit)
        )
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.budget.check_width(value.len(), self.limit)?;
        if self.limit == Limit::TextBytes {
            self.budget.charge_payload(value.len())?;
        }
        Ok(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.budget.check_width(value.len(), self.limit)?;
        if self.limit == Limit::TextBytes {
            self.budget.charge_payload(value.len())?;
        }
        Ok(value)
    }
}

/// One tagged `{"type": ..., "value": ...}` field value at `depth` enclosing
/// lists. Charges one node before anything else.
#[derive(Clone, Copy)]
struct FieldValueSeed<'b, 'l> {
    budget: &'b Budget<'l>,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for FieldValueSeed<'_, '_> {
    type Value = FieldValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.charge_node()?;
        deserializer.deserialize_struct("FieldValue", &["type", "value"], self)
    }
}

impl<'de> Visitor<'de> for FieldValueSeed<'_, '_> {
    type Value = FieldValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a tagged field value object with `type` and `value`")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut tag: Option<Tag> = None;
        let mut value: Option<FieldValue> = None;
        let mut buffered: Option<Buffered> = None;
        while let Some(field) = map.next_key::<ValueField>()? {
            match field {
                ValueField::Type => {
                    if tag.is_some() {
                        return Err(de::Error::duplicate_field("type"));
                    }
                    let parsed = map.next_value::<Tag>()?;
                    if let Some(pending) = buffered.take() {
                        value = Some(pending.into_value(parsed, self.budget)?);
                    }
                    tag = Some(parsed);
                }
                ValueField::Value => {
                    if value.is_some() || buffered.is_some() {
                        return Err(de::Error::duplicate_field("value"));
                    }
                    match tag {
                        Some(tag) => {
                            value = Some(map.next_value_seed(TypedValueSeed {
                                budget: self.budget,
                                depth: self.depth,
                                tag,
                            })?);
                        }
                        None => {
                            buffered = Some(map.next_value_seed(BufferedSeed {
                                budget: self.budget,
                                depth: self.depth,
                            })?);
                        }
                    }
                }
            }
        }
        match (tag, value) {
            (Some(_), Some(value)) => Ok(value),
            (None, _) => Err(de::Error::missing_field("type")),
            (Some(_), None) => Err(de::Error::missing_field("value")),
        }
    }
}

/// The `value` of a field whose `type` is already known.
#[derive(Clone, Copy)]
struct TypedValueSeed<'b, 'l> {
    budget: &'b Budget<'l>,
    depth: usize,
    tag: Tag,
}

impl<'de> DeserializeSeed<'de> for TypedValueSeed<'_, '_> {
    type Value = FieldValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let budget = self.budget;
        match self.tag {
            Tag::Bool => {
                budget.charge_payload(BOOL_PAYLOAD_BYTES)?;
                bool::deserialize(deserializer).map(FieldValue::Bool)
            }
            Tag::Unsigned => {
                budget.charge_payload(INTEGER_PAYLOAD_BYTES)?;
                u64::deserialize(deserializer).map(FieldValue::Unsigned)
            }
            Tag::Signed => {
                budget.charge_payload(INTEGER_PAYLOAD_BYTES)?;
                i64::deserialize(deserializer).map(FieldValue::Signed)
            }
            Tag::Text => BoundedString {
                budget,
                limit: Limit::TextBytes,
            }
            .deserialize(deserializer)
            .map(FieldValue::Text),
            Tag::Bytes => BytesSeed { budget }
                .deserialize(deserializer)
                .map(FieldValue::Bytes),
            Tag::Ipv4 => {
                budget.charge_payload(IPV4_PAYLOAD_BYTES)?;
                Ipv4Addr::deserialize(deserializer).map(FieldValue::Ipv4)
            }
            Tag::Ipv6 => {
                budget.charge_payload(IPV6_PAYLOAD_BYTES)?;
                Ipv6Addr::deserialize(deserializer).map(FieldValue::Ipv6)
            }
            Tag::Mac => {
                budget.charge_payload(MAC_PAYLOAD_BYTES)?;
                <[u8; 6]>::deserialize(deserializer).map(FieldValue::Mac)
            }
            Tag::List => ListSeed {
                budget,
                depth: self.depth,
            }
            .deserialize(deserializer)
            .map(FieldValue::List),
        }
    }
}

/// A byte value: each byte is charged against the per-value and total payload
/// budgets before it is pushed.
#[derive(Clone, Copy)]
struct BytesSeed<'b, 'l> {
    budget: &'b Budget<'l>,
}

impl<'de> DeserializeSeed<'de> for BytesSeed<'_, '_> {
    type Value = Bytes;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for BytesSeed<'_, '_> {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "an array of at most {} byte values",
            self.budget.limits.max_byte_value_bytes
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let maximum = self.budget.limits.max_byte_value_bytes;
        if let Some(hint) = sequence.size_hint() {
            self.budget.check_width(hint, Limit::ByteValueBytes)?;
        }
        let mut bytes = Vec::with_capacity(
            self.budget
                .bounded_capacity(sequence.size_hint(), Limit::ByteValueBytes),
        );
        while let Some(byte) = sequence.next_element::<u8>()? {
            if bytes.len() >= maximum {
                return Err(self.budget.exceeded(Limit::ByteValueBytes));
            }
            self.budget.charge_payload(1)?;
            bytes.push(byte);
        }
        Ok(Bytes::from(bytes))
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        self.budget
            .check_width(value.len(), Limit::ByteValueBytes)?;
        self.budget.charge_payload(value.len())?;
        Ok(Bytes::copy_from_slice(value))
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        self.budget
            .check_width(value.len(), Limit::ByteValueBytes)?;
        self.budget.charge_payload(value.len())?;
        Ok(Bytes::from(value))
    }
}

/// A list value at `depth` enclosing lists. Entering it consumes nesting;
/// every item consumes per-list and aggregate list budget before it is
/// deserialized, and the item itself charges its own node.
#[derive(Clone, Copy)]
struct ListSeed<'b, 'l> {
    budget: &'b Budget<'l>,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ListSeed<'_, '_> {
    type Value = Vec<FieldValue>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.budget.enter_list(self.depth)?;
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ListSeed<'_, '_> {
    type Value = Vec<FieldValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a list of at most {} tagged field values",
            self.budget.limits.max_list_items
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if let Some(hint) = sequence.size_hint() {
            self.budget.check_width(hint, Limit::ListItems)?;
        }
        let mut values = Vec::with_capacity(
            self.budget
                .bounded_capacity(sequence.size_hint(), Limit::ListItems),
        );
        loop {
            if let Some(limit) = self.budget.list_budget_full(values.len()) {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(self.budget.exceeded(limit));
                }
                return Ok(values);
            }
            self.budget.charge_list_item()?;
            let Some(value) = sequence.next_element_seed(FieldValueSeed {
                budget: self.budget,
                depth: self.depth.saturating_add(1),
            })?
            else {
                self.budget.refund_list_item();
                return Ok(values);
            };
            values.push(value);
        }
    }
}

/// A `value` that arrived before its `type`.
///
/// The value is retained under the most expensive interpretation it could
/// still have: strings are text, and sequence elements are charged as list
/// items, nodes, and payload bytes at once. A document that puts `value`
/// first therefore fits a slightly narrower envelope than the same document
/// with `type` first, but never a wider one.
enum Buffered {
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Text(String),
    Seq(Vec<BufferedItem>),
}

enum BufferedItem {
    Unsigned(u64),
    Signed(i64),
    Value(FieldValue),
}

impl Buffered {
    fn into_value<E: de::Error>(self, tag: Tag, budget: &Budget<'_>) -> Result<FieldValue, E> {
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

impl Tag {
    const fn expected(self) -> &'static str {
        match self {
            Self::Bool => "a boolean",
            Self::Unsigned => "an unsigned integer",
            Self::Signed => "a signed integer",
            Self::Text => "a string",
            Self::Bytes => "an array of bytes",
            Self::Ipv4 => "an IPv4 address string",
            Self::Ipv6 => "an IPv6 address string",
            Self::Mac => "an array of 6 bytes",
            Self::List => "a list of tagged field values",
        }
    }
}

#[derive(Clone, Copy)]
struct BufferedSeed<'b, 'l> {
    budget: &'b Budget<'l>,
    depth: usize,
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
