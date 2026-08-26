// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use packetcraftr_core::field::{FieldKind, text_form};
use packetcraftr_core::layer::{Id, Tier};
use packetcraftr_core::protocol::builtin;

#[test]
fn every_optional_field_has_default_and_required_derived_do_not() {
    let registry = builtin::registry().expect("built-in registry should be valid");
    for id in registry.protocols() {
        let Some(schema) = registry.schema(id) else {
            continue;
        };
        for field in schema.fields {
            match field.tier {
                // Optional fields either carry a constant default or are
                // absent when omitted (`default: None`); both are legal.
                Tier::Optional => {}
                Tier::Required | Tier::Derived => {
                    assert!(
                        field.default.is_none(),
                        "protocol {} field {} is {:?} but has default {:?}",
                        id,
                        field.name,
                        field.tier,
                        field.default
                    );
                }
            }
        }
    }
}

#[test]
fn constructible_optional_fields_match_their_defaults_in_text_form() {
    let registry = builtin::registry().expect("built-in registry should be valid");
    for id in registry.protocols() {
        let codec = registry.codec(id).expect("codec must exist");
        if let Ok(layer) = codec.make_layer(&BTreeMap::new()) {
            let Some(schema) = registry.schema(id) else {
                continue;
            };
            for field in schema.fields {
                if field.tier == Tier::Optional {
                    let Some(expected_default) = field.default else {
                        assert!(
                            layer.field(field.name).is_none(),
                            "protocol {} field {} has no default but a fresh layer exposes it",
                            id,
                            field.name
                        );
                        continue;
                    };
                    if let Some(val) = layer.field(field.name) {
                        let actual_text = text_form(&val);
                        assert_eq!(
                            actual_text, expected_default,
                            "protocol {} field {} default text mismatch",
                            id, field.name
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn list_fields_have_element_kinds_and_non_list_fields_do_not() {
    let registry = builtin::registry().expect("built-in registry should be valid");
    for id in registry.protocols() {
        let Some(schema) = registry.schema(id) else {
            continue;
        };
        for field in schema.fields {
            if field.kind == FieldKind::List {
                assert!(
                    field.element.is_some(),
                    "protocol {} list field {} must have element kind",
                    id,
                    field.name
                );
            } else {
                assert!(
                    field.element.is_none(),
                    "protocol {} non-list field {} must not have element kind",
                    id,
                    field.name
                );
            }
        }
    }
}

#[test]
fn unsigned_fields_have_max_values() {
    let registry = builtin::registry().expect("built-in registry should be valid");
    for id in registry.protocols() {
        let Some(schema) = registry.schema(id) else {
            continue;
        };
        for field in schema.fields {
            if field.kind == FieldKind::Unsigned {
                assert!(
                    field.max.is_some(),
                    "protocol {} unsigned field {} must have max value",
                    id,
                    field.name
                );
            }
        }
    }
}

#[test]
fn wire_field_returns_some_exactly_for_derived_fields_on_sample_layers() {
    let registry = builtin::registry().expect("built-in registry should be valid");
    let sample_protocols = ["ipv4", "udp", "tcp", "ethernet"];
    for proto_name in sample_protocols {
        let id = Id::new(proto_name);
        let codec = registry.codec(&id).expect("codec must exist");
        let layer = codec
            .make_layer(&BTreeMap::new())
            .expect("sample layer should construct");
        let schema = registry.schema(&id).expect("schema must exist");
        for field in schema.fields {
            let wire = layer.wire_field(field.name);
            if field.tier == Tier::Derived {
                assert!(
                    wire.is_some(),
                    "protocol {proto_name} field {} is Derived but wire_field returned None",
                    field.name
                );
            } else {
                assert!(
                    wire.is_none(),
                    "protocol {proto_name} field {} is {:?} but wire_field returned Some({wire:?})",
                    field.name,
                    field.tier
                );
            }
        }
    }
}

#[test]
fn dns_and_tls_are_decode_only_and_ipv4_is_not() {
    let registry = builtin::registry().expect("built-in registry should be valid");
    let dns_schema = registry.schema(&Id::new("dns")).expect("dns schema");
    let tls_schema = registry.schema(&Id::new("tls")).expect("tls schema");
    let ipv4_schema = registry.schema(&Id::new("ipv4")).expect("ipv4 schema");

    assert!(
        dns_schema.decode_only,
        "dns schema must have decode_only == true"
    );
    assert!(
        tls_schema.decode_only,
        "tls schema must have decode_only == true"
    );
    assert!(
        !ipv4_schema.decode_only,
        "ipv4 schema must have decode_only == false"
    );
}
