// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use packetcraftr::packet::document::{Format, Packet as PacketDocument};
use serde_json::{json, Value};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn json_file(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn validator(name: &str) -> Validator {
    let schema = json_file(root().join("schemas").join(name));
    jsonschema::draft202012::meta::validate(&schema)
        .unwrap_or_else(|error| panic!("{name} is not valid Draft 2020-12: {error}"));
    jsonschema::draft202012::new(&schema).unwrap()
}

#[test]
fn committed_schemas_and_every_document_example_validate() {
    let packet = validator("packetcraftr.packet.v1.schema.json");
    let output = validator("packetcraftr.output.v1.schema.json");
    let examples = root().join("examples/documents");

    for entry in fs::read_dir(&examples).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy();
        if name.starts_with("packet-") {
            let value = match path.extension().and_then(|extension| extension.to_str()) {
                Some("json") => json_file(&path),
                Some("yaml") => {
                    let input = fs::read_to_string(&path).unwrap();
                    serde_json::to_value(
                        PacketDocument::parse(&input, Format::Yaml, 1024 * 1024).unwrap(),
                    )
                    .unwrap()
                }
                _ => continue,
            };
            assert!(
                packet.is_valid(&value),
                "{name}: {:?}",
                packet.iter_errors(&value).collect::<Vec<_>>()
            );
        } else if name.starts_with("output-") && path.extension().is_some_and(|ext| ext == "json") {
            let value = json_file(&path);
            assert!(
                output.is_valid(&value),
                "{name}: {:?}",
                output.iter_errors(&value).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn every_ndjson_line_is_an_independently_valid_record() {
    let output = validator("packetcraftr.output.v1.schema.json");
    let fixture =
        fs::read(root().join("tests/fixtures/captures/pcapng/multi-link.pcapng")).unwrap();
    let capture = root().join("target/schema-contract.pcapng");
    fs::create_dir_all(capture.parent().unwrap()).unwrap();
    fs::write(&capture, fixture).unwrap();

    let result = std::process::Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(["--output", "ndjson", "read"])
        .arg(&capture)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    for (index, line) in result
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let value: Value = serde_json::from_slice(line).unwrap();
        assert!(
            output.is_valid(&value),
            "record {index}: {:?}",
            output.iter_errors(&value).collect::<Vec<_>>()
        );
    }
}

#[test]
fn schemas_reject_representative_contract_violations() {
    let packet = validator("packetcraftr.packet.v1.schema.json");
    let output = validator("packetcraftr.output.v1.schema.json");

    for malformed in [
        json!({"schema": "packetcraftr.packet/v1"}),
        json!({"schema": "packetcraftr.packet/v1", "layers": [{"protocol": ""}]}),
        json!({"schema": "packetcraftr.packet/v1", "layers": [{"protocol": "raw", "fields": {"bytes": {"type": "bytes", "value": [256]}}}]}),
        json!({"schema": "packetcraftr.packet/v1", "layers": [], "extra": true}),
    ] {
        assert!(
            !packet.is_valid(&malformed),
            "accepted malformed packet {malformed}"
        );
    }

    for malformed in [
        json!({"schema": "packetcraftr.output/v1", "command": "build", "mode": "aggregate", "status": "success", "diagnostics": []}),
        json!({"schema": "packetcraftr.output/v1", "command": "unknown", "mode": "aggregate", "status": "error", "error": {}, "diagnostics": []}),
        json!({"schema": "packetcraftr.output/v1", "command": "build", "mode": "stream", "status": "success", "sequence": 0, "result": {}, "diagnostics": []}),
    ] {
        assert!(
            !output.is_valid(&malformed),
            "accepted malformed output {malformed}"
        );
    }
}
