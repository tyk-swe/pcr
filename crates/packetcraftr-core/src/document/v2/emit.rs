// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use super::types::{Document, Layer, Value};
use crate::build::{Builder, Context, Options};
use crate::decode::DecodedPacket;
use crate::document::error::Error;
use crate::field::{FieldKind, FieldValue, WireValue, text_form};
use crate::layer::{FieldSchema, Raw, Tier};
use crate::registry::Registry;

/// Result of minimizing derived fields during document emission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Minimized {
    /// Derived fields were omitted because rebuilding with `auto` reproduced original wire bytes.
    Derived,
    /// Derived fields were retained as literals because rebuild differed or failed.
    FullLiterals,
    /// Minimization was skipped (`full = true`).
    Skipped,
}

impl Document {
    /// Emits a v2 document from a decoded packet with rebuild-and-compare minimization.
    pub fn from_decoded(
        decoded: &DecodedPacket,
        registry: &Arc<Registry>,
        full: bool,
    ) -> (Self, Minimized) {
        if full {
            let mut layers = Vec::with_capacity(decoded.packet.len());
            for (index, layer) in decoded.packet.iter().enumerate() {
                if layer.schema().decode_only {
                    let range = decoded.layout.layer(index).map(|l| l.range);
                    let bytes = range
                        .and_then(|r| decoded.original.get(r.start..r.end))
                        .map(|slice| decoded.original.slice_ref(slice))
                        .unwrap_or_default();
                    layers.push(Layer {
                        protocol: "raw".to_owned(),
                        fields: vec![(
                            "bytes".to_owned(),
                            Value::ScalarTyped {
                                text: text_form(&FieldValue::Bytes(bytes)),
                                kind: FieldKind::Bytes,
                            },
                        )],
                    });
                } else {
                    let protocol = layer.protocol_id().to_string();
                    let mut fields = Vec::new();
                    for field_schema in layer.schema().fields {
                        if let Some(wire) = layer.wire_field(field_schema.name) {
                            match wire {
                                WireValue::Raw(bytes) => {
                                    fields.push((field_schema.name.to_owned(), Value::Raw(bytes)));
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
                                WireValue::Auto => {
                                    fields.push((field_schema.name.to_owned(), Value::Auto));
                                }
                            }
                        } else if let Some(field_val) = layer.field(field_schema.name) {
                            fields.push((
                                field_schema.name.to_owned(),
                                field_val_to_v2_value(&field_val, field_schema),
                            ));
                        }
                    }
                    layers.push(Layer { protocol, fields });
                }
            }
            return (Self { layers }, Minimized::Skipped);
        }

        // Check if rebuild with Auto on derived fields reproduces original bytes
        let mut test_packet = crate::Packet::with_capacity(decoded.packet.len());
        for (index, layer) in decoded.packet.iter().enumerate() {
            if layer.schema().decode_only {
                let range = decoded.layout.layer(index).map(|l| l.range);
                let bytes = range
                    .and_then(|r| decoded.original.get(r.start..r.end))
                    .map(|slice| decoded.original.slice_ref(slice))
                    .unwrap_or_default();
                test_packet.push_boxed(Box::new(Raw::new(bytes)));
            } else {
                let mut cloned = layer.clone_box();
                for field_schema in cloned.schema().fields {
                    if field_schema.is_derived() {
                        let _ = cloned
                            .set_field(field_schema.name, FieldValue::Text("auto".to_owned()));
                    }
                }
                test_packet.push_boxed(cloned);
            }
        }

        let builder = Builder::new(Arc::clone(registry));
        let build_result = builder.build(test_packet, Context::default(), Options::default());

        let status = match build_result {
            Ok(built) if built.bytes == decoded.original => Minimized::Derived,
            _ => Minimized::FullLiterals,
        };

        let mut layers = Vec::with_capacity(decoded.packet.len());
        for (index, layer) in decoded.packet.iter().enumerate() {
            if layer.schema().decode_only {
                let range = decoded.layout.layer(index).map(|l| l.range);
                let bytes = range
                    .and_then(|r| decoded.original.get(r.start..r.end))
                    .map(|slice| decoded.original.slice_ref(slice))
                    .unwrap_or_default();
                layers.push(Layer {
                    protocol: "raw".to_owned(),
                    fields: vec![(
                        "bytes".to_owned(),
                        Value::ScalarTyped {
                            text: text_form(&FieldValue::Bytes(bytes)),
                            kind: FieldKind::Bytes,
                        },
                    )],
                });
            } else {
                let protocol = layer.protocol_id().to_string();
                let mut fields = Vec::new();
                for field_schema in layer.schema().fields {
                    match field_schema.tier {
                        Tier::Required => {
                            if let Some(val) = layer.field(field_schema.name) {
                                fields.push((
                                    field_schema.name.to_owned(),
                                    field_val_to_v2_value(&val, field_schema),
                                ));
                            }
                        }
                        Tier::Derived => {
                            if status == Minimized::FullLiterals {
                                if let Some(wire) = layer.wire_field(field_schema.name) {
                                    match wire {
                                        WireValue::Raw(bytes) => {
                                            fields.push((
                                                field_schema.name.to_owned(),
                                                Value::Raw(bytes),
                                            ));
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
                                        WireValue::Auto => {
                                            fields
                                                .push((field_schema.name.to_owned(), Value::Auto));
                                        }
                                    }
                                } else if let Some(val) = layer.field(field_schema.name) {
                                    fields.push((
                                        field_schema.name.to_owned(),
                                        field_val_to_v2_value(&val, field_schema),
                                    ));
                                }
                            }
                        }
                        Tier::Optional => {
                            if let Some(val) = layer.field(field_schema.name) {
                                let text = text_form(&val);
                                if let Some(default_str) = field_schema.default
                                    && text == default_str
                                {
                                    continue;
                                }
                                fields.push((
                                    field_schema.name.to_owned(),
                                    field_val_to_v2_value(&val, field_schema),
                                ));
                            }
                        }
                    }
                }
                layers.push(Layer { protocol, fields });
            }
        }

        (Self { layers }, status)
    }

    /// Serializes this v2 document as pretty-printed 2-space JSON.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(|source| Error::Serialize {
            format: "JSON",
            message: source.to_string(),
        })
    }

    /// Serializes this v2 document as bare YAML without a leading `---`.
    pub fn to_yaml_string(&self) -> Result<String, Error> {
        let text = noyalib::to_string(self).map_err(|source| Error::Serialize {
            format: "YAML",
            message: source.to_string(),
        })?;
        let bare = text
            .strip_prefix("---\n")
            .or_else(|| text.strip_prefix("--- "))
            .unwrap_or(&text);
        Ok(bare.to_owned())
    }
}

fn field_val_to_v2_value(val: &FieldValue, schema: &FieldSchema) -> Value {
    match val {
        FieldValue::List(items) => {
            let strings = items.iter().map(text_form).collect();
            Value::List(strings)
        }
        FieldValue::Bytes(bytes) if schema.is_derived() => Value::Raw(bytes.clone()),
        other => Value::ScalarTyped {
            text: text_form(other),
            kind: schema.kind,
        },
    }
}
