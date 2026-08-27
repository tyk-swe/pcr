// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::types::{Document, Layer, Value};
use crate::build::DEFAULT_MAX_LAYERS;
use crate::document::error::Error;
use crate::layer::Tier;
use crate::registry::Registry;

impl Document {
    /// Upgrades a parsed v1 packet document to minimized v2 document format.
    pub fn from_v1(v1: &crate::document::Packet, registry: &Registry) -> Result<Self, Error> {
        let packet = v1.to_packet(registry, DEFAULT_MAX_LAYERS)?;
        let full = Self::from_packet(&packet);

        let mut layers = Vec::with_capacity(full.layers.len());
        for (index, layer) in full.layers.into_iter().enumerate() {
            let Some(model_layer) = packet.layer(index) else {
                layers.push(layer);
                continue;
            };

            let mut fields = Vec::new();
            for (field_name, value) in layer.fields {
                let Some(field_schema) = model_layer
                    .schema()
                    .fields
                    .iter()
                    .find(|f| f.name == field_name)
                else {
                    fields.push((field_name, value));
                    continue;
                };

                match field_schema.tier {
                    Tier::Required => {
                        fields.push((field_name, value));
                    }
                    Tier::Derived => {
                        let default_has_field = registry
                            .codec_named(&layer.protocol)
                            .and_then(|codec| {
                                codec.make_layer(&std::collections::BTreeMap::new()).ok()
                            })
                            .and_then(|dl| dl.field(field_schema.name))
                            .is_some();
                        if !default_has_field || !matches!(value, Value::Auto) {
                            fields.push((field_name, value));
                        }
                    }
                    Tier::Optional => {
                        let list_text;
                        let text = match &value {
                            Value::Scalar(s) | Value::ScalarTyped { text: s, .. } => s.as_str(),
                            Value::List(items) => {
                                list_text = format!("[{}]", items.join(","));
                                list_text.as_str()
                            }
                            _ => "",
                        };
                        if let Some(default_str) = field_schema.default
                            && text == default_str
                        {
                            continue;
                        }
                        fields.push((field_name, value));
                    }
                }
            }
            layers.push(Layer {
                protocol: layer.protocol,
                fields,
            });
        }

        Ok(Self { layers })
    }
}
