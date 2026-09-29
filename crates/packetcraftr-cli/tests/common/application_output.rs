// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;

use serde_json::Value;

use super::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success};

/// Checks that application output charges compact event payloads in every format.
pub(crate) fn assert_exact_budget(
    command: &str,
    capture: &Path,
    event_collections: &[(&str, &str)],
    expected_text: &str,
    error_message: &str,
    error_causes: &[&str],
) {
    let path = path_text(capture);
    let document = parse_json(&run_success(&["--output", "json", command, path]));
    let total: usize = event_collections
        .iter()
        .flat_map(|&(_, key)| {
            document["result"][key]
                .as_array()
                .expect("application event collection must be an array")
        })
        .map(|value| {
            serde_json::to_vec(value)
                .expect("event payload must serialize")
                .len()
        })
        .sum();
    let exact = total.to_string();
    let under = total
        .checked_sub(1)
        .expect("fixture must have application event output")
        .to_string();

    for format in ["json", "ndjson", "text"] {
        let success = run_success(&[
            "--output",
            format,
            command,
            path,
            "--max-application-output-bytes",
            &exact,
        ]);
        match format {
            "json" => assert_eq!(parse_json(&success)["result"], document["result"]),
            "ndjson" => {
                let records = parse_ndjson(&success);
                assert_terminal(&records, "complete");
                for &(event, key) in event_collections {
                    let values = records
                        .iter()
                        .filter(|record| record["event"] == event)
                        .map(|record| record["result"].clone())
                        .collect();
                    assert_eq!(Value::Array(values), document["result"][key], "{event}");
                }
            }
            "text" => assert_eq!(
                String::from_utf8(success.stdout).expect("application text must be UTF-8"),
                expected_text,
            ),
            _ => unreachable!(),
        }

        let failure = run(&[
            "--output",
            format,
            command,
            path,
            "--max-application-output-bytes",
            &under,
        ]);
        assert_eq!(
            failure.status.code(),
            Some(6),
            "{command} {format}: {failure:?}"
        );
        let error = match format {
            "json" => parse_json(&failure)["error"].clone(),
            "ndjson" => {
                let records = parse_ndjson(&failure);
                assert_terminal(&records, "error");
                records.last().expect("terminal record exists")["error"].clone()
            }
            "text" => continue,
            _ => unreachable!(),
        };
        assert_eq!(error["code"], "policy.denied", "{command} {format}");
        assert_eq!(error["kind"], "policy", "{command} {format}");
        assert_eq!(error["message"], error_message, "{command} {format}");
        assert_eq!(
            error["causes"],
            serde_json::json!(error_causes),
            "{command} {format}"
        );
    }
}

fn assert_terminal(records: &[Value], event: &str) {
    assert_contiguous(records);
    let (terminal, preceding) = records
        .split_last()
        .expect("stream must have a terminal record");
    assert_eq!(terminal["event"], event);
    assert!(
        preceding
            .iter()
            .all(|record| !matches!(record["event"].as_str(), Some("complete" | "error"))),
        "stream must contain exactly one terminal record: {records:?}",
    );
}
