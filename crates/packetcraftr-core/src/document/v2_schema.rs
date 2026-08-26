// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! JSON Schema generation for `packetcraftr.packet/v2` packet documents.
//!
//! Emits a deterministic JSON Schema directly from registered protocol
//! codecs, their reflection schemas, tiers, defaults, and aliases.

use serde_json::{Map, Value};

use crate::field::FieldKind;
use crate::layer::{FieldSchema, Tier};
use crate::registry::Registry;

const SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const SCHEMA_ID: &str =
    "https://raw.githubusercontent.com/tyk-swe/pcr/main/schemas/packetcraftr.packet.v2.schema.json";
const SCHEMA_COMMENT: &str = "SPDX-License-Identifier: AGPL-3.0-only";
const SCHEMA_TITLE: &str = "PacketcraftR packet document v2";
const SCHEMA_DESCRIPTION: &str = "A runtime-neutral ordered packet stack. Protocol-specific field names and semantic constraints are generated from packetcraftr_core::registry::Registry.";
const PACKET_DOCUMENT_SCHEMA_V2: &str = "packetcraftr.packet/v2";

const BYTES_PATTERN: &str = "^0[xX]([0-9a-fA-F]{2})*$";
const UNSIGNED_PATTERN: &str = "^(0[xX][0-9a-fA-F]+|[0-9]+)$";
const SIGNED_PATTERN: &str = "^-?(0[xX][0-9a-fA-F]+|[0-9]+)$";
const MAC_PATTERN: &str = "^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$";

/// Emits the JSON Schema for `packetcraftr.packet/v2` packet documents from
/// the given protocol registry as a [`serde_json::Value`].
///
/// Output is deterministic and derived directly from the registry's protocols,
/// codecs, and layer reflection schemas.
#[must_use]
pub fn emit(registry: &Registry) -> Value {
    let mut root = Map::new();
    root.insert(
        "$schema".to_string(),
        Value::String(SCHEMA_DRAFT.to_string()),
    );
    root.insert("$id".to_string(), Value::String(SCHEMA_ID.to_string()));
    root.insert(
        "$comment".to_string(),
        Value::String(SCHEMA_COMMENT.to_string()),
    );
    root.insert("title".to_string(), Value::String(SCHEMA_TITLE.to_string()));
    root.insert(
        "description".to_string(),
        Value::String(SCHEMA_DESCRIPTION.to_string()),
    );
    root.insert("type".to_string(), Value::String("object".to_string()));
    root.insert(
        "required".to_string(),
        Value::Array(vec![
            Value::String("schema".to_string()),
            Value::String("layers".to_string()),
        ]),
    );

    let mut properties = Map::new();

    let mut schema_prop = Map::new();
    schema_prop.insert(
        "const".to_string(),
        Value::String(PACKET_DOCUMENT_SCHEMA_V2.to_string()),
    );
    schema_prop.insert(
        "description".to_string(),
        Value::String("Packet document schema identifier.".to_string()),
    );
    properties.insert("schema".to_string(), Value::Object(schema_prop));

    let mut layers_prop = Map::new();
    layers_prop.insert("type".to_string(), Value::String("array".to_string()));
    layers_prop.insert("minItems".to_string(), Value::from(1));
    layers_prop.insert(
        "description".to_string(),
        Value::String("Layers in outermost-to-innermost wire order.".to_string()),
    );
    let mut items_ref = Map::new();
    items_ref.insert(
        "$ref".to_string(),
        Value::String("#/$defs/layer".to_string()),
    );
    layers_prop.insert("items".to_string(), Value::Object(items_ref));
    properties.insert("layers".to_string(), Value::Object(layers_prop));

    root.insert("properties".to_string(), Value::Object(properties));
    root.insert("additionalProperties".to_string(), Value::Bool(false));

    let defs = emit_defs(registry);
    root.insert("$defs".to_string(), Value::Object(defs));

    Value::Object(root)
}

/// Emits the pretty-formatted JSON Schema for `packetcraftr.packet/v2` packet
/// documents from the given protocol registry with two-space indentation and a
/// trailing newline.
///
/// # Panics
///
/// Panics only if in-memory serialization of [`serde_json::Value`] fails.
#[must_use]
pub fn emit_pretty(registry: &Registry) -> String {
    let value = emit(registry);
    let mut rendered = serde_json::to_string_pretty(&value)
        .expect("in-memory JSON Schema value serialization cannot fail");
    rendered.push('\n');
    rendered
}

fn emit_defs(registry: &Registry) -> Map<String, Value> {
    let mut defs = Map::new();

    let mut layer_one_of = Vec::new();

    for protocol in registry.protocols() {
        let Some(schema) = registry.schema(protocol) else {
            continue;
        };
        let Some(codec) = registry.codec(protocol) else {
            continue;
        };
        let aliases = codec.aliases();

        // 1. Add branch to layer oneOf
        let mut branch_props = Map::new();
        let ref_val = {
            let mut r = Map::new();
            r.insert(
                "$ref".to_string(),
                Value::String(format!("#/$defs/{protocol}")),
            );
            Value::Object(r)
        };

        branch_props.insert(protocol.to_string(), ref_val.clone());
        for alias in aliases {
            branch_props.insert((*alias).to_string(), ref_val.clone());
        }

        let mut branch = Map::new();
        branch.insert("type".to_string(), Value::String("object".to_string()));
        branch.insert("properties".to_string(), Value::Object(branch_props));
        branch.insert("additionalProperties".to_string(), Value::Bool(false));
        layer_one_of.push(Value::Object(branch));

        // 2. Add protocol def
        let protocol_def = emit_protocol_def(schema);
        defs.insert(protocol.to_string(), Value::Object(protocol_def));
    }

    let mut layer_def = Map::new();
    layer_def.insert("type".to_string(), Value::String("object".to_string()));
    layer_def.insert("minProperties".to_string(), Value::from(1));
    layer_def.insert("maxProperties".to_string(), Value::from(1));
    layer_def.insert(
        "description".to_string(),
        Value::String(
            "One protocol layer keyed by canonical identifier or registered alias.".to_string(),
        ),
    );
    layer_def.insert("oneOf".to_string(), Value::Array(layer_one_of));
    defs.insert("layer".to_string(), Value::Object(layer_def));

    defs
}

fn emit_protocol_def(schema: &crate::layer::Schema) -> Map<String, Value> {
    let mut def = Map::new();
    def.insert("type".to_string(), Value::String("object".to_string()));

    let description = if schema.decode_only {
        format!("{}; decode-only; build rejects this layer", schema.name)
    } else {
        schema.name.to_string()
    };
    def.insert("description".to_string(), Value::String(description));

    if schema.decode_only {
        def.insert("x-packetcraftr-decode-only".to_string(), Value::Bool(true));
    }

    let mut properties = Map::new();
    let mut required_fields = Vec::new();

    for field in schema.fields {
        if field.tier == Tier::Required {
            required_fields.push(Value::String(field.name.to_string()));
        }

        let field_schema = emit_field_schema(field);
        properties.insert(field.name.to_string(), Value::Object(field_schema.clone()));
        for alias in field.aliases {
            properties.insert((*alias).to_string(), Value::Object(field_schema.clone()));
        }
    }

    def.insert("properties".to_string(), Value::Object(properties));
    if !required_fields.is_empty() {
        def.insert("required".to_string(), Value::Array(required_fields));
    }
    def.insert("additionalProperties".to_string(), Value::Bool(false));

    def
}

fn emit_field_schema(field: &FieldSchema) -> Map<String, Value> {
    let mut field_map = Map::new();

    let mut desc = field.description.to_string();
    match field.tier {
        Tier::Derived => {
            desc.push_str("; derived (auto)");
        }
        Tier::Optional => {
            if let Some(default) = field.default {
                desc.push_str("; default ");
                desc.push_str(default);
            }
        }
        Tier::Required => {}
    }
    if !field.aliases.is_empty() {
        desc.push_str("; aliases: ");
        desc.push_str(&field.aliases.join(", "));
    }

    let tier_str = match field.tier {
        Tier::Required => "required",
        Tier::Derived => "derived",
        Tier::Optional => "optional",
    };

    field_map.insert("description".to_string(), Value::String(desc));
    field_map.insert(
        "x-packetcraftr-tier".to_string(),
        Value::String(tier_str.to_string()),
    );

    if field.tier == Tier::Derived {
        let base = base_kind_schema(field.kind, field.element, field.max);
        let auto_schema = {
            let mut m = Map::new();
            m.insert("const".to_string(), Value::String("auto".to_string()));
            Value::Object(m)
        };
        let raw_schema = {
            let mut m = Map::new();
            m.insert("type".to_string(), Value::String("object".to_string()));
            m.insert(
                "required".to_string(),
                Value::Array(vec![Value::String("raw".to_string())]),
            );
            m.insert("additionalProperties".to_string(), Value::Bool(false));
            let mut raw_prop = Map::new();
            raw_prop.insert("type".to_string(), Value::String("string".to_string()));
            raw_prop.insert(
                "pattern".to_string(),
                Value::String(BYTES_PATTERN.to_string()),
            );
            let mut props = Map::new();
            props.insert("raw".to_string(), Value::Object(raw_prop));
            m.insert("properties".to_string(), Value::Object(props));
            Value::Object(m)
        };

        field_map.insert(
            "oneOf".to_string(),
            Value::Array(vec![Value::Object(base), auto_schema, raw_schema]),
        );
    } else {
        let base = base_kind_schema(field.kind, field.element, field.max);
        for (key, val) in base {
            field_map.insert(key, val);
        }
    }

    field_map
}

fn base_kind_schema(
    kind: FieldKind,
    element: Option<FieldKind>,
    max: Option<u64>,
) -> Map<String, Value> {
    let mut map = Map::new();
    match kind {
        FieldKind::Bool => {
            map.insert("type".to_string(), Value::String("boolean".to_string()));
        }
        FieldKind::Unsigned => {
            let mut int_schema = Map::new();
            int_schema.insert("type".to_string(), Value::String("integer".to_string()));
            int_schema.insert("minimum".to_string(), Value::from(0));
            if let Some(maximum) = max {
                int_schema.insert("maximum".to_string(), Value::from(maximum));
            }
            let mut str_schema = Map::new();
            str_schema.insert("type".to_string(), Value::String("string".to_string()));
            str_schema.insert(
                "pattern".to_string(),
                Value::String(UNSIGNED_PATTERN.to_string()),
            );
            map.insert(
                "oneOf".to_string(),
                Value::Array(vec![Value::Object(int_schema), Value::Object(str_schema)]),
            );
        }
        FieldKind::Signed => {
            let mut int_schema = Map::new();
            int_schema.insert("type".to_string(), Value::String("integer".to_string()));
            let mut str_schema = Map::new();
            str_schema.insert("type".to_string(), Value::String("string".to_string()));
            str_schema.insert(
                "pattern".to_string(),
                Value::String(SIGNED_PATTERN.to_string()),
            );
            map.insert(
                "oneOf".to_string(),
                Value::Array(vec![Value::Object(int_schema), Value::Object(str_schema)]),
            );
        }
        FieldKind::Text => {
            map.insert("type".to_string(), Value::String("string".to_string()));
        }
        FieldKind::Bytes => {
            map.insert("type".to_string(), Value::String("string".to_string()));
            map.insert(
                "pattern".to_string(),
                Value::String(BYTES_PATTERN.to_string()),
            );
        }
        FieldKind::Ipv4 => {
            map.insert("type".to_string(), Value::String("string".to_string()));
            map.insert("format".to_string(), Value::String("ipv4".to_string()));
        }
        FieldKind::Ipv6 => {
            map.insert("type".to_string(), Value::String("string".to_string()));
            map.insert("format".to_string(), Value::String("ipv6".to_string()));
        }
        FieldKind::Mac => {
            map.insert("type".to_string(), Value::String("string".to_string()));
            map.insert(
                "pattern".to_string(),
                Value::String(MAC_PATTERN.to_string()),
            );
        }
        FieldKind::List => {
            let elem_schema = if let Some(elem) = element {
                base_kind_schema(elem, None, None)
            } else {
                let mut fallback = Map::new();
                fallback.insert("type".to_string(), Value::String("string".to_string()));
                fallback
            };
            map.insert("type".to_string(), Value::String("array".to_string()));
            map.insert("items".to_string(), Value::Object(elem_schema));
        }
    }
    map
}
