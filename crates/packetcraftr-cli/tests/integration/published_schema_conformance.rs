// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::Value;

use crate::common;

use common::schema_validator;

fn validator(schema: &str) -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(schema).expect("published schema must be JSON");
    jsonschema::validator_for(&schema).expect("published schema must compile")
}

fn rewrite_v2_validator() -> jsonschema::Validator {
    validator(include_str!(
        "../../../../schemas/packetcraftr.rewrite.v2.schema.json"
    ))
}

/// Every published example document validates against the schema it names,
/// so an example cannot drift from a contract without failing here. The YAML
/// packet example is parsed by the document parser and validated through its
/// serialized form, since the schema describes the JSON representation.
#[test]
fn every_published_declared_schema() {
    use packetcraftr_core::document::{DEFAULT_MAX_DOCUMENT_BYTES, Format, Packet};

    let packet_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.packet.v2.schema.json"
    ));
    let udp_profiles_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.udp-profiles.v1.schema.json"
    ));
    let rewrite_v2 = rewrite_v2_validator();
    let service_probes_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.service-probes.v1.schema.json"
    ));
    let service_exclusions_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.service-exclusions.v1.schema.json"
    ));
    let os_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.os-fingerprints.v1.schema.json"
    ));
    let output_validator = schema_validator();
    let v6_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.output.v6.schema.json"
    ));
    let v7_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.output.v7.schema.json"
    ));
    let v8_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.output.v8.schema.json"
    ));
    let v9_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.output.v9.schema.json"
    ));
    let v10_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.output.v10.schema.json"
    ));

    let v11_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.output.v11.schema.json"
    ));
    let v14_validator = common::frozen_v14_schema_validator();
    let v15_validator = common::frozen_v15_schema_validator();

    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/documents");
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .expect("published examples directory")
        .map(|entry| entry.expect("example entry").path())
        .collect();
    paths.sort();

    let mut validated = 0_usize;
    let mut failures = Vec::new();
    for path in &paths {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(path).expect("example must be UTF-8");
        let document: Value = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{name} must be JSON: {error}")),
            Some("yaml") => {
                let packet = Packet::parse(&text, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES)
                    .unwrap_or_else(|error| panic!("{name} must be a packet document: {error}"));
                serde_json::to_value(packet).expect("packet documents serialize")
            }
            other => panic!("{name}: unexpected example extension {other:?}"),
        };
        let schema = document["schema"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} must declare a schema"));
        let validator = match schema {
            "packetcraftr.output/v18" => output_validator,
            "packetcraftr.output/v17" => common::frozen_v17_schema_validator(),
            "packetcraftr.output/v16" => common::frozen_v16_schema_validator(),
            "packetcraftr.output/v15" => v15_validator,
            "packetcraftr.output/v14" => v14_validator,
            "packetcraftr.output/v11" => &v11_validator,
            "packetcraftr.output/v10" => &v10_validator,
            "packetcraftr.output/v9" => &v9_validator,
            "packetcraftr.output/v8" => &v8_validator,
            "packetcraftr.output/v7" => &v7_validator,
            "packetcraftr.output/v6" => &v6_validator,
            "packetcraftr.packet/v2" => &packet_validator,
            "packetcraftr.rewrite/v2" => &rewrite_v2,
            "packetcraftr.udp-profiles/v1" => &udp_profiles_validator,
            "packetcraftr.service-probes/v1" => &service_probes_validator,
            "packetcraftr.service-exclusions/v1" => &service_exclusions_validator,
            "packetcraftr.os-fingerprints/v1" => &os_validator,
            other => panic!("{name} declares an unknown schema {other}"),
        };
        if let Err(error) = validator.validate(&document) {
            failures.push(format!("{name}: {error}"));
        }
        validated += 1;
    }
    assert!(
        failures.is_empty(),
        "invalid examples:\n{}",
        failures.join("\n")
    );
    assert!(
        validated > 100,
        "expected every published example to be validated, saw {validated}"
    );
}
