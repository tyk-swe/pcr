// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::{Value, json};

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

#[test]
fn scan_listing_accepts_port_zero_in_json_and_ndjson() {
    for format in ["json", "ndjson"] {
        let output = common::run_success(&[
            "--output",
            format,
            "scan",
            "192.0.2.1",
            "--list",
            "--ports",
            "0",
        ]);
        let report = if format == "json" {
            common::parse_json(&output)
        } else {
            let records = common::parse_ndjson(&output);
            let complete = records.last().expect("completion record");
            assert_eq!(complete["event"], "complete");
            complete.clone()
        };
        assert_eq!(
            report["result"]["ports"]["endpoints"],
            json!([{"transport": "tcp", "port": 0}]),
        );
    }
}

#[test]
fn schema_accepts_based_source_reject_zero() {
    let original: Value = serde_json::from_str(include_str!(
        "../../../../examples/documents/output-read-dissect-event.json"
    ))
    .expect("published read example must be JSON");
    common::frozen_v10_schema_validator()
        .validate(&original)
        .unwrap();
    for (validator, family) in [
        (
            common::frozen_v10_schema_validator(),
            packetcraftr_cli::output::contract::SCHEMA_V10,
        ),
        (
            schema_validator(),
            packetcraftr_cli::output::contract::SCHEMA_V11,
        ),
    ] {
        let mut document = original.clone();
        document["schema"] = family.into();
        document["result"]["source_frame"] = json!(1);
        validator
            .validate(&document)
            .unwrap_or_else(|error| panic!("source frame 1 is valid in {family}: {error}"));
        document["result"]["source_frame"] = json!(0);
        assert!(
            validator.validate(&document).is_err(),
            "source frame 0 is invalid in {family}"
        );
    }
}

#[test]
fn service_probe_ascii_fields_agree_with_runtime_validation() {
    use packetcraftr_core::document::service_probes;

    let schema = validator(include_str!(
        "../../../../schemas/packetcraftr.service-probes.v1.schema.json"
    ));
    let original: Value = serde_json::from_str(include_str!(
        "../../../packetcraftr/data/service-probes.json"
    ))
    .unwrap();
    for character in (0..=127).map(char::from).chain(['é', '中', '🦀']) {
        for version_stop in [false, true] {
            let mut document = original.clone();
            let expected = character.is_ascii() && (version_stop || !character.is_ascii_control());
            if version_stop {
                document["matches"][0]["version"]["stop_at"] = character.to_string().into();
            } else {
                document["matches"][0]["prefix"] = format!("OpenSSH_{character}").into();
            }
            assert_eq!(
                service_probes::parse(&serde_json::to_vec(&document).unwrap()).is_ok(),
                expected,
                "parser: {character:?}, version stop: {version_stop}"
            );
            assert_eq!(
                schema.is_valid(&document),
                expected,
                "schema: {character:?}, version stop: {version_stop}"
            );
        }
    }
}

#[test]
fn service_document_text_fields_agree_on_control_characters() {
    use packetcraftr_core::document::{service_exclusions, service_probes};

    for probes in [true, false] {
        let (schema, original, mut paths) = if probes {
            (
                validator(include_str!(
                    "../../../../schemas/packetcraftr.service-probes.v1.schema.json"
                )),
                serde_json::from_str::<Value>(include_str!(
                    "../../../packetcraftr/data/service-probes.json"
                ))
                .unwrap(),
                vec![
                    "/version".to_owned(),
                    "/matches/0/product".to_owned(),
                    "/probes/0/read_only_review/reviewed_by".to_owned(),
                    "/probes/0/read_only_review/statement".to_owned(),
                ],
            )
        } else {
            (
                validator(include_str!(
                    "../../../../schemas/packetcraftr.service-exclusions.v1.schema.json"
                )),
                serde_json::from_str::<Value>(include_str!(
                    "../../../packetcraftr/data/service-exclusions.json"
                ))
                .unwrap(),
                vec!["/version".to_owned(), "/entries/0/reason".to_owned()],
            )
        };
        let metadata = if probes {
            &["/probes/0/metadata", "/matches/0/metadata"][..]
        } else {
            &["/entries/0/metadata"][..]
        };
        for base in metadata {
            for field in ["source", "reference", "license", "maintainer"] {
                paths.push(format!("{base}/{field}"));
            }
        }
        for path in paths {
            for character in (0..=159)
                .map(char::from)
                .chain(['é', '中', '🦀', '\u{2028}', '\u{2029}'])
            {
                let mut document = original.clone();
                *document.pointer_mut(&path).expect("text fixture field") =
                    format!("text{character}").into();
                let bytes = serde_json::to_vec(&document).unwrap();
                let accepted = if probes {
                    service_probes::parse(&bytes).is_ok()
                } else {
                    service_exclusions::parse(&bytes).is_ok()
                };
                assert_eq!(
                    accepted,
                    !character.is_control(),
                    "parser: {path}, {character:?}"
                );
                assert_eq!(
                    schema.is_valid(&document),
                    accepted,
                    "schema: {path}, {character:?}"
                );
            }
        }
        let mut dates: Vec<_> = metadata
            .iter()
            .map(|base| format!("{base}/updated"))
            .collect();
        if probes {
            dates.push("/probes/0/read_only_review/reviewed".to_owned());
        }
        for path in dates {
            for date in ["2026-10-09", "٢٠٢٦-١٠-٠٩", "२०२६-१०-०९"] {
                let mut document = original.clone();
                *document.pointer_mut(&path).expect("date fixture field") = date.into();
                let bytes = serde_json::to_vec(&document).unwrap();
                let accepted = if probes {
                    service_probes::parse(&bytes).is_ok()
                } else {
                    service_exclusions::parse(&bytes).is_ok()
                };
                assert_eq!(accepted, date.is_ascii(), "parser date: {path}, {date}");
                assert_eq!(
                    schema.is_valid(&document),
                    accepted,
                    "schema date: {path}, {date}"
                );
            }
        }
    }
}

#[test]
fn rewrite_v2_reject_assignment_properties() {
    let document = json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [{"assign": [{"field": "ipv4.ttl", "value": 63, "occurrence": 2}]}],
    });
    assert!(!rewrite_v2_validator().is_valid(&document));
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
            "packetcraftr.output/v11" => output_validator,
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
