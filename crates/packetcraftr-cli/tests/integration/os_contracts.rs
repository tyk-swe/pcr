// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde_json::Value;
use tempfile::TempDir;

use crate::common::{self, parse_json, parse_ndjson, path_text, run, schema_validator};

#[test]
fn malformed_window_scale_remains_a_bounded_wire_observation() {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../../examples/documents/output-os-probe.json"
    ))
    .unwrap();
    value["schema"] = packetcraftr_cli::output::contract::SCHEMA_V17.into();
    value["result"]["observation"]["suitable"] = false.into();
    value["result"]["observation"]["tcp"]["window_scale"] = 255.into();
    assert!(schema_validator().is_valid(&value));
    value["result"]["observation"]["tcp"]["window_scale"] = 256.into();
    assert!(!schema_validator().is_valid(&value));
}

#[test]
fn invalid_requests_documents_and_policy_refusals_are_terminal_errors() {
    for target in ["example.test", "0.0.0.0", "224.0.0.1"] {
        let output = parse_json(&run(&[
            "--output",
            "json",
            "identify-os",
            target,
            "--open-port",
            "80",
            "--closed-port",
            "81",
        ]));
        assert_eq!(output["command"], "identify-os");
        assert_eq!(output["status"], "error");
        assert_eq!(output["error"]["kind"], "usage");
        assert!(schema_validator().is_valid(&output));
    }
    let denied = parse_json(&run(&[
        "--output",
        "json",
        "identify-os",
        "192.0.2.2",
        "--open-port",
        "80",
        "--closed-port",
        "81",
        "--allow-destination",
        "198.51.100.0/24",
    ]));
    assert_eq!(denied["error"]["kind"], "policy");
    assert!(schema_validator().is_valid(&denied));
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("invalid.json");
    for bytes in [
        b"{}".to_vec(),
        vec![b' '; packetcraftr_core::document::os_fingerprints::MAX_DOCUMENT_BYTES + 1],
    ] {
        std::fs::write(&path, bytes).unwrap();
        let stream = parse_ndjson(&run(&[
            "--output",
            "ndjson",
            "identify-os",
            "192.0.2.2",
            "--open-port",
            "80",
            "--closed-port",
            "81",
            "--corpus",
            path_text(&path),
        ]));
        assert_eq!(stream.len(), 1);
        assert_eq!(stream[0]["sequence"], 0);
        assert_eq!(stream[0]["event"], "error");
        assert_eq!(stream[0]["error"]["kind"], "usage");
        assert!(schema_validator().is_valid(&stream[0]));
    }
}

#[test]
fn os_result_contract_rejects_unknown_semantics_and_unqualified_candidates() {
    let mut output: Value = serde_json::from_str(include_str!(
        "../../../../examples/documents/output-os.json"
    ))
    .unwrap();
    output["schema"] = packetcraftr_cli::output::contract::SCHEMA_V17.into();
    assert!(schema_validator().is_valid(&output));
    for (field, value) in [("outcome", "certain"), ("outcome", "unknown")] {
        let mut changed = output.clone();
        changed["result"]["identification"][field] = value.into();
        assert!(!schema_validator().is_valid(&changed));
    }
    let mut changed = output.clone();
    changed["result"]["identification"]["candidates"][0]["confidence"] = "probable".into();
    assert!(!schema_validator().is_valid(&changed));
    let mut changed = output;
    changed["result"]["observations"][0]["probe"] = "unsolicited".into();
    assert!(!schema_validator().is_valid(&changed));
}

#[test]
fn actual_native_ndjson_obeys_schema_sequence_and_terminal_contracts() {
    let records: Vec<Value> =
        serde_json::from_str(include_str!("../fixtures/os-native-stream.json")).unwrap();
    let validator = common::frozen_v14_schema_validator();
    for (sequence, record) in records.iter().enumerate() {
        assert_eq!(record["sequence"], sequence);
        assert_eq!(record["command"], "identify-os");
        assert!(
            validator.is_valid(record),
            "invalid native record {sequence}"
        );
        assert_eq!(record["event"] == "complete", sequence == records.len() - 1);
        assert_ne!(record["event"], "error");
    }
    let terminal = records.last().unwrap();
    assert_eq!(terminal["result"]["identification"]["outcome"], "matched");
    assert!(terminal["stats"]["packets_attempted"].as_u64().unwrap() <= 32);
}
