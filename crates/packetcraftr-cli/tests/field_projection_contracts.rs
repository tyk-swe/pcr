// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use std::io::Write;

use common::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success};
use serde_json::Value;
const IP: &str = "45000014000000004001f6e7c0000201c6336402";

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
fn innermost_layers_list_selectors_and_frame_facts_project_as_values() {
    let packet = "ipv4(src=192.0.2.1,dst=192.0.2.2)/ipv4(src=198.51.100.1,dst=198.51.100.2)/udp(sport=40000,dport=53)/dns(id=7,response=true,questions=[{name=\"example.test.\",type=1,class=1}],answers=[{owner=\"a.test.\",ttl=60,value={kind=a,address=192.0.2.8}}])";
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
        "ipv4#last.source",
        "--field",
        "ipv4#-1.destination",
        "--field",
        "dns.answers[*].owner",
        "--field",
        "dns.answers[-1].ttl",
        "--field",
        "frame.layer_count",
        "--field",
        "frame.protocols",
        "--field",
        "frame.truncated",
    ]));
    assert_eq!(
        result["result"]["rows"][0]["values"],
        serde_json::json!([
            "198.51.100.1",
            "198.51.100.2",
            ["a.test."],
            60,
            4,
            ["ipv4", "ipv4", "udp", "dns"],
            false
        ])
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

#[test]
fn projection_byte_limit_counts_the_rendered_json_payload() {
    let dissect = [
        "dissect",
        "--hex",
        IP,
        "--link-type",
        "228",
        "--field",
        "frame.number",
    ];
    let mut json = vec!["--output", "json"];
    json.extend(dissect);
    let report = parse_json(&run_success(&json));
    let row = report["result"]["rows"][0].clone();
    let row_length = serde_json::to_vec(&row).unwrap().len();
    let exact = row_length.to_string();
    let mut json = vec!["--output", "json"];
    json.extend(dissect);
    json.extend(["--max-projection-bytes", exact.as_str()]);
    let limited = parse_json(&run_success(&json));
    assert_eq!(limited["result"]["rows"][0], row);
    let under = (row_length - 1).to_string();
    let mut json = vec!["--output", "json"];
    json.extend(dissect);
    json.extend(["--max-projection-bytes", under.as_str()]);
    let output = run(&json);
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(
        parse_json(&output)["error"]["code"],
        "policy.projection_limit"
    );
    let mut stream = vec!["--output", "ndjson"];
    stream.extend(dissect);
    let records = parse_ndjson(&run_success(&stream));
    let fields = records[0]["result"].clone();
    let fields_length = serde_json::to_vec(&fields).unwrap().len();
    let exact = fields_length.to_string();
    let mut stream = vec!["--output", "ndjson"];
    stream.extend(dissect);
    stream.extend(["--max-projection-bytes", exact.as_str()]);
    let limited = parse_ndjson(&run_success(&stream));
    assert_contiguous(&limited);
    assert_eq!(
        limited
            .iter()
            .map(|record| record["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["fields", "complete"]
    );
    assert_eq!(limited[0]["result"], fields);
    let under = (fields_length - 1).to_string();
    let mut stream = vec!["--output", "ndjson"];
    stream.extend(dissect);
    stream.extend(["--max-projection-bytes", under.as_str()]);
    let output = run(&stream);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "error");
    assert_eq!(records[0]["sequence"], 0);
    assert_eq!(records[0]["error"]["code"], "policy.projection_limit");
}

fn read_rows(path: &str, fields: &[&str], filter: Option<&str>) -> Vec<Value> {
    let mut args = vec!["--output", "json", "read", path];
    for field in fields {
        args.extend(["--field", field]);
    }
    if let Some(filter) = filter {
        args.extend(["--filter", filter]);
    }
    let report = parse_json(&run_success(&args));
    assert_eq!(report["result"]["frames_read"], 3, "{args:?}");
    report["result"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["values"].clone())
        .collect()
}

#[test]
fn read_projection_evaluates_the_physical_frame_with_or_without_stream_fields() {
    let packet = format!(
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/tcp(sport=40000,dport=80)/raw(text={})",
        "x".repeat(1200)
    );
    let fragments = run_success(&[
        "--output", "pcap", "fragment", "--mtu", "576", "--packet", &packet,
    ]);
    let mut capture = tempfile::NamedTempFile::new().unwrap();
    capture.write_all(&fragments.stdout).unwrap();
    let path = path_text(capture.path());
    let plain = ["frame.number", "tcp.dstport"];
    let streamed = ["frame.number", "tcp.dstport", "tcp.stream"];

    for filter in ["tcp.dstport == 80", "tcp.dstport == 80 && tcp.stream == 0"] {
        assert_eq!(read_rows(path, &plain, Some(filter)), Vec::<Value>::new());
        assert_eq!(
            read_rows(path, &streamed, Some(filter)),
            Vec::<Value>::new()
        );
    }
    assert_eq!(
        read_rows(path, &plain, None),
        [
            serde_json::json!([1, null]),
            serde_json::json!([2, null]),
            serde_json::json!([3, null])
        ]
    );
    assert_eq!(
        read_rows(path, &streamed, None),
        [
            serde_json::json!([1, null, null]),
            serde_json::json!([2, null, null]),
            serde_json::json!([3, null, null])
        ]
    );
}
