// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::common;
use std::path::PathBuf;

use common::{parse_json, run_success};

fn multiplexed() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http2-multiplexed.pcapng")
}
fn upgrade() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures/http2-upgrade.pcapng")
}

#[test]
fn multiplexed_capture_reports_all_frame_types_and_messages() {
    let path = multiplexed();
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&[
        "--output", "json", "analyze", "http2", path,
    ]));
    let result = &document["result"];
    let summary = &result["summary"];
    assert_eq!(summary["connections"], 1);
    assert_eq!(summary["prior_knowledge_connections"], 1);
    assert_eq!(summary["issues"], 0, "{document}");
    let messages = result["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 7, "{document}");
    let kinds: Vec<_> = messages
        .iter()
        .map(|m| m["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "request",
            "request",
            "push_promise",
            "response",
            "response",
            "response",
            "request"
        ],
        "{document}"
    );
    let stream3 = messages
        .iter()
        .find(|m| m["http2_stream_id"] == 3 && m["kind"] == "response")
        .expect("stream 3 response");
    assert_eq!(stream3["body_bytes"], 5);
    let stream1 = messages
        .iter()
        .find(|m| m["http2_stream_id"] == 1 && m["kind"] == "response")
        .expect("stream 1 response");
    assert_eq!(stream1["body_bytes"], 3);
    assert_eq!(stream1["trailers"][0]["name"], "age");
    assert_eq!(stream1["trailers"][0]["value"], "3");
    let pushed = messages
        .iter()
        .find(|m| m["http2_stream_id"] == 2 && m["kind"] == "response")
        .expect("pushed response");
    assert_eq!(pushed["status"], "complete");
    let types: Vec<u64> = result["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|frame| frame["frame_type"].as_u64().unwrap())
        .collect();
    assert_eq!(
        types,
        [
            4, 4, 4, 4, 1, 1, 9, 5, 1, 0, 1, 0, 1, 1, 1, 3, 6, 6, 2, 8, 7, 7
        ],
        "{document}"
    );
    let connection = &result["connections"][0];
    assert_eq!(connection["startup"], "prior_knowledge");
    assert_eq!(connection["status"], "complete");
    assert_eq!(connection["streams"], 4);
    assert_eq!(connection["pending_pings"], 0);
}

#[test]
fn upgrade_capture_reports_h2c_connection() {
    let path = upgrade();
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "http2",
        path.to_str().unwrap(),
    ]));
    let result = &document["result"];
    assert_eq!(result["summary"]["upgraded_connections"], 1, "{document}");
    let connection = &result["connections"][0];
    assert_eq!(connection["startup"], "h2c");
    assert_eq!(connection["status"], "complete");
    assert_eq!(connection["streams"], 1);
    let response = connection["upgrade_response"].as_object().unwrap();
    assert_eq!(response["start"]["status"], 101);
    let request = result["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["kind"] == "request")
        .expect("upgrade request");
    assert_eq!(request["http2_stream_id"], 1);
    assert_eq!(request["body_bytes"], 4);
    assert_eq!(request["upgrade_head"]["start"]["method"], "POST");
    let response = result["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["kind"] == "response")
        .expect("upgrade response");
    assert_eq!(response["body_bytes"], 5);
}
