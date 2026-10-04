// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};
const IP: &str = "45000014000000004001f6e7c0000201c6336402";

#[test]
fn proj_byte_json_payload() {
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
