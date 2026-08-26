// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use super::types::{Document, Layer, Value, field_path};
use crate::document::error::Error;
use crate::field::{FieldKind, FieldValue, WireValue, coerce, coerce_kind, text_form};
use crate::layer::{FieldError, FieldSchema};
use crate::registry::Registry;

impl Document {
    /// Converts this v2 document to a strongly typed packet model.
    pub fn to_packet(
        &self,
        registry: &Registry,
        max_layers: usize,
    ) -> Result<crate::Packet, Error> {
        if self.layers.len() > max_layers {
            return Err(Error::LayerLimit { limit: max_layers });
        }

        let mut packet = crate::Packet::with_capacity(self.layers.len());

        for (layer_index, layer) in self.layers.iter().enumerate() {
            let codec =
                registry
                    .codec_named(&layer.protocol)
                    .ok_or_else(|| Error::UnknownProtocol {
                        layer: layer_index,
                        protocol: layer.protocol.clone(),
                    })?;

            let schema = registry
                .schema(&codec.protocol_id())
                .or_else(|| codec.published_schema())
                .ok_or_else(|| Error::UnknownProtocol {
                    layer: layer_index,
                    protocol: layer.protocol.clone(),
                })?;
            if schema.decode_only {
                let path = field_path(&self.layers, layer_index, "");
                return Err(Error::DecodeOnly {
                    path,
                    protocol: layer.protocol.clone(),
                });
            }

            let mut seen_canonical: BTreeMap<&'static str, String> = BTreeMap::new();
            let mut field_map = BTreeMap::new();

            for (field_key, value) in &layer.fields {
                let field_schema = schema
                    .fields
                    .iter()
                    .find(|f| f.name == field_key || f.aliases.contains(&field_key.as_str()))
                    .ok_or_else(|| {
                        let path = field_path(&self.layers, layer_index, field_key);
                        Error::UnknownField {
                            path,
                            field: field_key.clone(),
                        }
                    })?;

                if let Some(prev_key) = seen_canonical.get(field_schema.name) {
                    let path = field_path(&self.layers, layer_index, field_schema.name);
                    let alias = if prev_key != field_schema.name {
                        prev_key.clone()
                    } else {
                        field_key.clone()
                    };
                    return Err(Error::DuplicateField {
                        path,
                        canonical: field_schema.name.to_owned(),
                        alias,
                    });
                }
                seen_canonical.insert(field_schema.name, field_key.clone());

                let path = field_path(&self.layers, layer_index, field_schema.name);
                let field_value = match value {
                    Value::Auto => {
                        if field_schema.kind == FieldKind::Text || field_schema.is_derived() {
                            FieldValue::Text("auto".to_owned())
                        } else {
                            return Err(Error::AutoNotDerived { path });
                        }
                    }
                    Value::Raw(bytes) => {
                        if field_schema.is_derived() || field_schema.kind == FieldKind::Bytes {
                            FieldValue::Bytes(bytes.clone())
                        } else {
                            return Err(Error::ValueForm {
                                path,
                                got: "{raw: 0x...}".to_owned(),
                                expected: expected_desc(field_schema),
                            });
                        }
                    }
                    Value::List(items) => {
                        if field_schema.kind != FieldKind::List {
                            return Err(Error::ValueForm {
                                path,
                                got: format!("[{}]", items.join(", ")),
                                expected: expected_desc(field_schema),
                            });
                        }
                        let element_kind = field_schema.element.unwrap_or(FieldKind::Text);
                        let mut elem_values = Vec::with_capacity(items.len());
                        for item in items {
                            let val = coerce_kind(element_kind, None, None, false, item)
                                .map_err(|e| map_coerce_error(e, &path, item, field_schema))?;
                            elem_values.push(val);
                        }
                        FieldValue::List(elem_values)
                    }
                    Value::Scalar(text) | Value::ScalarTyped { text, .. } => {
                        coerce(field_schema, text)
                            .map_err(|e| map_coerce_error(e, &path, text, field_schema))?
                    }
                };

                field_map.insert(field_schema.name.to_owned(), field_value);
            }

            for field_schema in schema.fields.iter().filter(|f| f.is_required()) {
                if !seen_canonical.contains_key(field_schema.name) {
                    let path = field_path(&self.layers, layer_index, field_schema.name);
                    return Err(Error::MissingRequired { path });
                }
            }

            let layer_instance = codec
                .make_layer(&field_map)
                .map_err(|source| Error::Layer {
                    layer: layer_index,
                    protocol: layer.protocol.clone(),
                    source,
                })?;

            layer_instance
                .validate_required_fields()
                .map_err(|source| match source {
                    FieldError::MissingRequired { field, .. } => {
                        let path = field_path(&self.layers, layer_index, &field);
                        Error::MissingRequired { path }
                    }
                    other => Error::Layer {
                        layer: layer_index,
                        protocol: layer.protocol.clone(),
                        source: crate::codec::Error::Field(other),
                    },
                })?;

            packet.push_boxed(layer_instance);
        }

        Ok(packet)
    }

    /// Converts a model packet into a full, un-minimized v2 document in schema order.
    pub fn from_packet(packet: &crate::Packet) -> Self {
        let mut layers = Vec::with_capacity(packet.len());

        for layer in packet.iter() {
            let protocol = layer.protocol_id().to_string();
            let mut fields = Vec::new();

            for field_schema in layer.schema().fields {
                if field_schema.is_derived() {
                    if let Some(wire) = layer.wire_field(field_schema.name) {
                        match wire {
                            WireValue::Auto => {
                                fields.push((field_schema.name.to_owned(), Value::Auto));
                            }
                            WireValue::Exact(val) => {
                                fields.push((
                                    field_schema.name.to_owned(),
                                    Value::ScalarTyped {
                                        text: val.to_string(),
                                        kind: field_schema.kind,
                                    },
                                ));
                            }
                            WireValue::Raw(bytes) => {
                                fields.push((field_schema.name.to_owned(), Value::Raw(bytes)));
                            }
                        }
                    } else if let Some(field_val) = layer.field(field_schema.name) {
                        match field_val {
                            FieldValue::Text(text) if text.eq_ignore_ascii_case("auto") => {
                                fields.push((field_schema.name.to_owned(), Value::Auto));
                            }
                            FieldValue::Bytes(bytes) if field_schema.kind != FieldKind::Bytes => {
                                fields.push((field_schema.name.to_owned(), Value::Raw(bytes)));
                            }
                            other => {
                                fields.push((
                                    field_schema.name.to_owned(),
                                    Value::ScalarTyped {
                                        text: text_form(&other),
                                        kind: field_schema.kind,
                                    },
                                ));
                            }
                        }
                    }
                } else if let Some(field_val) = layer.field(field_schema.name) {
                    match field_val {
                        FieldValue::List(items) => {
                            let strings = items.iter().map(text_form).collect::<Vec<_>>();
                            fields.push((field_schema.name.to_owned(), Value::List(strings)));
                        }
                        other => {
                            fields.push((
                                field_schema.name.to_owned(),
                                Value::ScalarTyped {
                                    text: text_form(&other),
                                    kind: field_schema.kind,
                                },
                            ));
                        }
                    }
                }
            }

            layers.push(Layer { protocol, fields });
        }

        Self { layers }
    }
}

fn map_coerce_error(
    error: crate::field::CoerceError,
    path: &str,
    _got: &str,
    _schema: &FieldSchema,
) -> Error {
    match error {
        crate::field::CoerceError::AutoNotDerived => Error::AutoNotDerived {
            path: path.to_owned(),
        },
        crate::field::CoerceError::OutOfRange { got, max } => Error::OutOfRange {
            path: path.to_owned(),
            got,
            max,
        },
        crate::field::CoerceError::ValueForm { expected, got } => Error::ValueForm {
            path: path.to_owned(),
            got,
            expected: expected.to_owned(),
        },
    }
}

fn expected_desc(schema: &FieldSchema) -> String {
    match schema.kind {
        FieldKind::Bool => "a boolean (true/false)".to_owned(),
        FieldKind::Unsigned => {
            if let Some(max) = schema.max {
                format!("an unsigned integer at most {max}")
            } else {
                "an unsigned integer (decimal or 0x hex)".to_owned()
            }
        }
        FieldKind::Signed => "a signed integer (decimal or 0x hex)".to_owned(),
        FieldKind::Text => "text".to_owned(),
        FieldKind::Bytes => "bytes as 0x followed by an even number of hex digits".to_owned(),
        FieldKind::Ipv4 => "an IPv4 address".to_owned(),
        FieldKind::Ipv6 => "an IPv6 address".to_owned(),
        FieldKind::Mac => "a MAC address".to_owned(),
        FieldKind::List => "a list of elements".to_owned(),
    }
}
