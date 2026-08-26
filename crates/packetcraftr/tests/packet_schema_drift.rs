// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Validates that `schemas/packetcraftr.packet.v2.schema.json` matches the
//! schema emitted directly from the registry, that the schema itself is valid
//! JSON Schema 2020-12, and that canonical documents validate as expected.

use std::fs;
use std::path::PathBuf;

use serde_json::json;

#[test]
fn schema_v2_matches_committed_file() {
    let registry = packetcraftr::core::protocol::builtin::registry().expect("built-in registry");
    let emitted = packetcraftr::core::document::v2_schema::emit_pretty(&registry);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/packetcraftr.packet.v2.schema.json");
    let committed = fs::read_to_string(&path).expect(
        "schemas/packetcraftr.packet.v2.schema.json must exist; run `packetcraftr schema emit --contract packet/v2 > schemas/packetcraftr.packet.v2.schema.json`",
    );
    assert_eq!(
        emitted, committed,
        "run `packetcraftr schema emit --contract packet/v2 > schemas/packetcraftr.packet.v2.schema.json`"
    );
}

#[test]
fn emitted_schema_is_valid_json_schema() {
    let registry = packetcraftr::core::protocol::builtin::registry().expect("built-in registry");
    let schema_json = packetcraftr::core::document::v2_schema::emit(&registry);
    let validator = jsonschema::validator_for(&schema_json);
    assert!(
        validator.is_ok(),
        "schema itself must be valid JSON Schema: {:?}",
        validator.err()
    );
}

#[test]
fn schema_v2_document_validation() {
    let registry = packetcraftr::core::protocol::builtin::registry().expect("built-in registry");
    let schema_json = packetcraftr::core::document::v2_schema::emit(&registry);
    let validator = jsonschema::validator_for(&schema_json).expect("valid schema");

    // Canonical v2 document validates successfully
    let valid_document = json!({
        "schema": "packetcraftr.packet/v2",
        "layers": [
            {
                "ethernet": {
                    "destination": "02:00:00:00:00:02",
                    "source": "02:00:00:00:00:01"
                }
            },
            {
                "ipv4": {
                    "source": "192.0.2.1",
                    "destination": "192.0.2.2",
                    "ttl": 64,
                    "checksum": "auto"
                }
            },
            {
                "udp": {
                    "source_port": 49152,
                    "destination_port": 9,
                    "checksum": {
                        "raw": "0xdead"
                    }
                }
            },
            {
                "raw": {
                    "bytes": "0x68656c6c6f"
                }
            }
        ]
    });
    assert!(
        validator.is_valid(&valid_document),
        "valid document must pass validation"
    );

    // Negative case 1: ttl: 300 (above maximum 255)
    let bad_ttl = json!({
        "schema": "packetcraftr.packet/v2",
        "layers": [
            {
                "ipv4": {
                    "source": "192.0.2.1",
                    "destination": "192.0.2.2",
                    "ttl": 300
                }
            }
        ]
    });
    assert!(
        !validator.is_valid(&bad_ttl),
        "ttl: 300 must fail validation"
    );

    // Negative case 2: unknown field
    let unknown_field = json!({
        "schema": "packetcraftr.packet/v2",
        "layers": [
            {
                "ipv4": {
                    "source": "192.0.2.1",
                    "destination": "192.0.2.2",
                    "unknown_field": 123
                }
            }
        ]
    });
    assert!(
        !validator.is_valid(&unknown_field),
        "unknown field must fail validation"
    );

    // Negative case 3: two-key layer
    let two_key_layer = json!({
        "schema": "packetcraftr.packet/v2",
        "layers": [
            {
                "ethernet": {
                    "destination": "02:00:00:00:00:02",
                    "source": "02:00:00:00:00:01"
                },
                "ipv4": {
                    "source": "192.0.2.1",
                    "destination": "192.0.2.2"
                }
            }
        ]
    });
    assert!(
        !validator.is_valid(&two_key_layer),
        "two-key layer must fail validation"
    );

    // Negative case 4: schema: packetcraftr.packet/v1
    let v1_schema_doc = json!({
        "schema": "packetcraftr.packet/v1",
        "layers": [
            {
                "raw": {
                    "bytes": "0x68656c6c6f"
                }
            }
        ]
    });
    assert!(
        !validator.is_valid(&v1_schema_doc),
        "v1 schema document must fail validation"
    );
}
