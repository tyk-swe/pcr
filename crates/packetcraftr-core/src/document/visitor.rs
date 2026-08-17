// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use super::types::{LAYER_LIMIT_SENTINEL, Layer, Packet};
use crate::field::FieldValue;

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
pub(super) enum PacketDocumentField {
    Schema,
    Layers,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
pub(super) enum LayerDocumentField {
    Protocol,
    Fields,
}

#[derive(Clone, Copy)]
pub(super) struct PacketDocumentSeed {
    pub(super) max_layers: usize,
}

impl<'de> DeserializeSeed<'de> for PacketDocumentSeed {
    type Value = Packet;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "PacketDocument",
            &["schema", "layers"],
            PacketDocumentVisitor {
                max_layers: self.max_layers,
            },
        )
    }
}

pub(super) struct PacketDocumentVisitor {
    pub(super) max_layers: usize,
}

impl<'de> Visitor<'de> for PacketDocumentVisitor {
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
        while let Some(field) = map.next_key::<PacketDocumentField>()? {
            match field {
                PacketDocumentField::Schema => {
                    if schema.is_some() {
                        return Err(de::Error::duplicate_field("schema"));
                    }
                    schema = Some(map.next_value()?);
                }
                PacketDocumentField::Layers => {
                    if layers.is_some() {
                        return Err(de::Error::duplicate_field("layers"));
                    }
                    layers = Some(map.next_value_seed(LayersSeed {
                        maximum: self.max_layers,
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
pub(super) struct LayersSeed {
    pub(super) maximum: usize,
}

impl<'de> DeserializeSeed<'de> for LayersSeed {
    type Value = Vec<Layer>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(LayersVisitor {
            maximum: self.maximum,
        })
    }
}

pub(super) struct LayersVisitor {
    pub(super) maximum: usize,
}

impl<'de> Visitor<'de> for LayersVisitor {
    type Value = Vec<Layer>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} packet layers", self.maximum)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|length| length > self.maximum)
        {
            return Err(de::Error::custom(LAYER_LIMIT_SENTINEL));
        }
        let mut layers = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
        while layers.len() < self.maximum {
            let Some(layer) = sequence.next_element_seed(LayerDocumentSeed)? else {
                return Ok(layers);
            };
            layers.push(layer);
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(LAYER_LIMIT_SENTINEL));
        }
        Ok(layers)
    }
}

#[derive(Clone, Copy)]
pub(super) struct LayerDocumentSeed;

impl<'de> DeserializeSeed<'de> for LayerDocumentSeed {
    type Value = Layer;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "LayerDocument",
            &["protocol", "fields"],
            LayerDocumentVisitor,
        )
    }
}

pub(super) struct LayerDocumentVisitor;

impl<'de> Visitor<'de> for LayerDocumentVisitor {
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
        while let Some(field) = map.next_key::<LayerDocumentField>()? {
            match field {
                LayerDocumentField::Protocol => {
                    if protocol.is_some() {
                        return Err(de::Error::duplicate_field("protocol"));
                    }
                    protocol = Some(map.next_value()?);
                }
                LayerDocumentField::Fields => {
                    if fields.is_some() {
                        return Err(de::Error::duplicate_field("fields"));
                    }
                    fields = Some(map.next_value_seed(FieldsSeed)?);
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
pub(super) struct FieldsSeed;

impl<'de> DeserializeSeed<'de> for FieldsSeed {
    type Value = BTreeMap<String, FieldValue>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(FieldsVisitor)
    }
}

pub(super) struct FieldsVisitor;

impl<'de> Visitor<'de> for FieldsVisitor {
    type Value = BTreeMap<String, FieldValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map of unique reflective field names")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = BTreeMap::new();
        while let Some(name) = map.next_key::<String>()? {
            if fields.contains_key(&name) {
                return Err(de::Error::custom(format!(
                    "duplicate reflective field {name:?}"
                )));
            }
            fields.insert(name, map.next_value()?);
        }
        Ok(fields)
    }
}
