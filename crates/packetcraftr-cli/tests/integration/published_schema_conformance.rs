// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::Value;

use crate::common;

use common::schema_validator;

fn validator(schema: &str) -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(schema).expect("published schema must be JSON");
    jsonschema::validator_for(&schema).expect("published schema must compile")
}

fn rewrite_schema_validator() -> jsonschema::Validator {
    validator(include_str!(
        "../../../../schemas/packetcraftr.rewrite.v1.schema.json"
    ))
}

/// Every published example document validates against the schema it names,
/// so an example cannot drift from a contract without failing here. The YAML
/// packet example is parsed by the document parser and validated through its
/// serialized form, since the schema describes the JSON representation.
#[test]
fn every_published_example_document_matches_its_declared_schema() {
    use packetcraftr_core::document::{DEFAULT_MAX_DOCUMENT_BYTES, Format, Packet};

    let packet_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.packet.v1.schema.json"
    ));
    let udp_profiles_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.udp-profiles.v1.schema.json"
    ));
    let rewrite_validator = rewrite_schema_validator();
    let service_probes_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.service-probes.v1.schema.json"
    ));
    let service_exclusions_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.service-exclusions.v1.schema.json"
    ));
    let os_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.os-fingerprints.v1.schema.json"
    ));
    let indicators_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.indicators.v1.schema.json"
    ));
    let output_validator = schema_validator();
    let scanner_validator = validator(include_str!(
        "../../../../schemas/packetcraftr.scanner-corpus.v1.schema.json"
    ));
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/documents");
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .expect("published examples directory")
        .map(|entry| entry.expect("example entry").path())
        .collect();
    paths.extend(
        std::fs::read_dir(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/consumers/fixtures"
        ))
        .unwrap()
        .map(|entry| entry.unwrap().path()),
    );
    paths.push(std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/scanner-corpus.v1.json"
    )));
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
            "packetcraftr.indicators/v1" => &indicators_validator,
            "packetcraftr.output/v1" => output_validator,
            "packetcraftr.packet/v1" => &packet_validator,
            "packetcraftr.rewrite/v1" => &rewrite_validator,
            "packetcraftr.udp-profiles/v1" => &udp_profiles_validator,
            "packetcraftr.service-probes/v1" => &service_probes_validator,
            "packetcraftr.service-exclusions/v1" => &service_exclusions_validator,
            "packetcraftr.os-fingerprints/v1" => &os_validator,
            "packetcraftr.scanner-corpus/v1" => &scanner_validator,
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

#[test]
fn reset_contracts_reject_unsupported_families_and_malformed_documents() {
    use packetcraftr_core::document::{DEFAULT_MAX_DOCUMENT_BYTES, Format, Packet};
    use packetcraftr_core::transform::{ChecksumMode, rules::Rules};

    let mut output: Value = serde_json::from_str(include_str!(
        "../../../../examples/documents/output-build-success.json"
    ))
    .unwrap();
    for version in [0, 2, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 999] {
        output["schema"] = format!("packetcraftr.output/v{version}").into();
        assert!(!schema_validator().is_valid(&output), "version {version}");
    }
    output["schema"] = "packetcraftr.output/v1".into();
    output.as_object_mut().unwrap().remove("result");
    assert!(!schema_validator().is_valid(&output));

    let packet_schema = validator(include_str!(
        "../../../../schemas/packetcraftr.packet.v1.schema.json"
    ));
    let packet = include_str!("../../../../examples/documents/packet-ipv4-udp.json");
    let rules = include_str!("../../../../examples/documents/rewrite-field-edits.json");
    let registry = packetcraftr_core::protocol::builtin::registry();
    assert!(Packet::parse(packet, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES).is_ok());
    assert!(Rules::parse(rules.as_bytes(), ChecksumMode::Repair, &registry).is_ok());
    for version in [0, 2, 999] {
        let mut document: Value = serde_json::from_str(packet).unwrap();
        document["schema"] = format!("packetcraftr.packet/v{version}").into();
        assert!(!packet_schema.is_valid(&document));
        assert!(
            packetcraftr_core::document::recipe::parse(
                &document.to_string(),
                Some(Format::Json),
                &registry,
                64
            )
            .is_err()
        );
        let yaml = format!("schema: packetcraftr.packet/v{version}\nlayers:\n  - protocol: raw\n");
        assert!(
            packetcraftr_core::document::recipe::parse(&yaml, Some(Format::Yaml), &registry, 64)
                .is_err()
        );

        let mut document: Value = serde_json::from_str(rules).unwrap();
        document["schema"] = format!("packetcraftr.rewrite/v{version}").into();
        assert!(!rewrite_schema_validator().is_valid(&document));
        assert!(
            Rules::parse(
                document.to_string().as_bytes(),
                ChecksumMode::Repair,
                &registry
            )
            .is_err()
        );
    }
    assert!(Packet::parse("{", Format::Json, DEFAULT_MAX_DOCUMENT_BYTES).is_err());
    assert!(Rules::parse(b"{", ChecksumMode::Repair, &registry).is_err());
}
