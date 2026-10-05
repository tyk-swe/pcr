// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use common::{parse_json, parse_ndjson, run};
#[test]
fn fail_set_invalid_opts_fail_before_work() {
    let records = parse_ndjson(&run(&[
        "--output",
        "ndjson",
        "--resource-diagnostics",
        "read",
        "missing-capture.pcap",
    ]));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "error");
    assert!(records[0].get("resources").is_some());
    for value in ["0", "3600001", "-1", "invalid"] {
        let output = run(&[
            "--output",
            "ndjson",
            "--output-timeout-ms",
            value,
            "read",
            "missing-capture.pcap",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(parse_ndjson(&output)[0]["error"]["kind"], "usage");
    }
    assert_eq!(
        run(&["--resource-diagnostics", "protocols"]).status.code(),
        Some(2)
    );
    let error = parse_json(&run(&[
        "--output",
        "json",
        "--output-timeout-ms",
        "1",
        "protocols",
    ]));
    assert_eq!(error["error"]["kind"], "usage");
}
