// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;
use support::{parse_json, parse_ndjson, run, run_success};
const IP: &str = "45000014000000004001f6e7c0000201c6336402";

fn schema(value: &serde_json::Value) {
    let source: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/packetcraftr.output.v5.schema.json"
    ))
    .unwrap();
    assert!(
        jsonschema::validator_for(&source).unwrap().is_valid(value),
        "{value}"
    );
}

#[test]
fn ordered_columns_missing_values_and_csv_quoting_are_explicit() {
    let args = [
        "dissect",
        "--hex",
        IP,
        "--link-type",
        "228",
        "--field",
        "frame.number",
        "--field",
        "ip.src",
        "--field",
        "udp.source_port",
    ];
    let mut json = vec!["--output", "json"];
    json.extend(args);
    let report = parse_json(&run_success(&json));
    schema(&report);
    assert_eq!(
        report["result"]["columns"],
        serde_json::json!(["frame.number", "ip.src", "udp.source_port"])
    );
    assert_eq!(
        report["result"]["rows"][0]["values"],
        serde_json::json!([1, "192.0.2.1", null])
    );
    let mut csv = vec!["--output", "csv"];
    csv.extend(args);
    let output = String::from_utf8(run_success(&csv).stdout).unwrap();
    assert_eq!(
        output,
        "\"frame.number\",\"ip.src\",\"udp.source_port\"\n\"1\",\"\"\"192.0.2.1\"\"\",\"null\"\n"
    );
    let mut stream = vec!["--output", "ndjson"];
    stream.extend(args);
    let records = parse_ndjson(&run_success(&stream));
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["event"], "fields");
    assert_eq!(records[1]["event"], "complete");
    for record in records {
        schema(&record);
    }
}

#[test]
fn repeated_layers_are_arrays_and_occurrence_selection_is_scalar() {
    let packet = "ipv4(src=192.0.2.1,dst=192.0.2.2)/ipv4(src=198.51.100.1,dst=198.51.100.2)/udp(sport=40000,dport=40001)";
    let built = parse_json(&run_success(&[
        "--output", "json", "build", "--packet", packet,
    ]));
    let hex = built["result"]["bytes_hex"].as_str().unwrap();
    let result = parse_json(&run_success(&[
        "--output",
        "json",
        "dissect",
        "--link-type",
        "228",
        "--hex",
        hex,
        "--field",
        "ipv4.source",
        "--field",
        "ipv4#2.source",
    ]));
    assert_eq!(
        result["result"]["rows"][0]["values"],
        serde_json::json!([["192.0.2.1", "198.51.100.1"], "198.51.100.1"])
    );
}

#[test]
fn capture_projection_retains_positions_indexes_and_resource_failures() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/tls-handshake.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "read",
        path.to_str().unwrap(),
        "--field",
        "frame.number",
        "--field",
        "tcp.stream",
        "--filter",
        "frame.number == 2",
    ]));
    schema(&report);
    assert_eq!(report["result"]["rows_written"], 1);
    assert_eq!(report["result"]["rows"][0]["source_frame"], 2);
    assert_eq!(report["result"]["rows"][0]["values"][0], 2);
    assert!(report["result"]["rows"][0]["values"][1].is_u64());
    let output = run(&[
        "--output",
        "ndjson",
        "read",
        path.to_str().unwrap(),
        "--field",
        "frame.number",
        "--max-projection-bytes",
        "1",
    ]);
    assert!(!output.status.success());
    assert_eq!(parse_ndjson(&output).last().unwrap()["event"], "error");
    let output = run(&[
        "--output",
        "json",
        "read",
        "/nonexistent",
        "--field",
        "unknown.field",
    ]);
    assert!(!output.status.success());
    assert_eq!(parse_json(&output)["error"]["code"], "cli.projection_field");
}
