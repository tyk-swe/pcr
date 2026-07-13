// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use packetcraftr::packet::document::{Format, Packet as PacketDocument};
use serde_json::{Value, json};

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
    let output = validator("packetcraftr.output.v2.schema.json");
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
    let output = validator("packetcraftr.output.v2.schema.json");
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
    let records = result
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    for (index, value) in records.iter().enumerate() {
        assert!(
            output.is_valid(value),
            "record {index}: {:?}",
            output.iter_errors(value).collect::<Vec<_>>()
        );
        assert_eq!(value["sequence"], index.to_string(), "record {index}");
    }
    assert_eq!(records.first().unwrap()["record"], "start");
    assert!(matches!(
        records.last().unwrap()["record"].as_str(),
        Some("complete" | "error" | "cancelled")
    ));
    assert_eq!(
        records
            .iter()
            .filter(|record| matches!(
                record["record"].as_str(),
                Some("complete" | "error" | "cancelled")
            ))
            .count(),
        1
    );
}

#[test]
fn schemas_reject_representative_contract_violations() {
    let packet = validator("packetcraftr.packet.v1.schema.json");
    let output = validator("packetcraftr.output.v2.schema.json");

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
        json!({"schema": "packetcraftr.output/v2", "command": "build", "mode": "aggregate", "status": "success", "diagnostics": []}),
        json!({"schema": "packetcraftr.output/v2", "tool": {"version": "0.3.0", "build_target": "x86_64-unknown-linux-gnu"}, "operation_id": "00", "command": "unknown", "mode": "aggregate", "effective_request": {}, "status": "error", "error": {}, "completion_reason": "completed", "diagnostics": []}),
        json!({"schema": "packetcraftr.output/v2", "tool": {"version": "0.3.0", "build_target": "x86_64-unknown-linux-gnu"}, "operation_id": "00000000000000000000000000000000", "command": "build", "mode": "stream", "record": "item", "status": "running", "sequence": 0, "result": {}, "diagnostics": []}),
    ] {
        assert!(
            !output.is_valid(&malformed),
            "accepted malformed output {malformed}"
        );
    }

    let mut numeric_length = json_file(root().join("examples/documents/output-build-success.json"));
    numeric_length["result"]["length"] = json!(4);
    assert!(
        !output.is_valid(&numeric_length),
        "output-v2 accepted a numeric 64-bit byte length"
    );
    let mut numeric_layout = json_file(root().join("examples/documents/output-build-success.json"));
    numeric_layout["result"]["layout"]["layers"][0]["index"] = json!(0);
    assert!(
        !output.is_valid(&numeric_layout),
        "output-v2 accepted a numeric platform-sized layout index"
    );

    let mut maximum_uint64 = json_file(root().join("examples/documents/output-build-success.json"));
    maximum_uint64["result"]["length"] = json!(u64::MAX.to_string());
    assert!(
        output.is_valid(&maximum_uint64),
        "output-v2 rejected the unsigned 64-bit maximum"
    );
    maximum_uint64["result"]["length"] = json!("18446744073709551616");
    assert!(
        !output.is_valid(&maximum_uint64),
        "output-v2 accepted a value above the unsigned 64-bit maximum"
    );

    let mut minimum_int64 = json_file(root().join("examples/documents/output-capture-event.json"));
    minimum_int64["result"]["frame"]["timestamp"]["unix_seconds"] = json!(i64::MIN.to_string());
    assert!(
        output.is_valid(&minimum_int64),
        "output-v2 rejected the signed 64-bit minimum"
    );
    minimum_int64["result"]["frame"]["timestamp"]["unix_seconds"] = json!("-9223372036854775809");
    assert!(
        !output.is_valid(&minimum_int64),
        "output-v2 accepted a value below the signed 64-bit minimum"
    );

    let mut item_with_terminal_result =
        json_file(root().join("examples/documents/output-capture-event.json"));
    item_with_terminal_result["result"] = json!({"event": "complete", "frames": "1"});
    assert!(
        !output.is_valid(&item_with_terminal_result),
        "output-v2 accepted a terminal result in an item record"
    );

    let mut terminal_with_item_result =
        json_file(root().join("examples/documents/output-dns-complete.json"));
    terminal_with_item_result["result"] =
        json_file(root().join("examples/documents/output-dns-event.json"))["result"].clone();
    assert!(
        !output.is_valid(&terminal_with_item_result),
        "output-v2 accepted an item result in a terminal record"
    );
}
