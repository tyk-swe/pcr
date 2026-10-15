// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `analyze quic` contracts: header-form evidence without decryption.

use std::path::PathBuf;

use serde_json::json;

use crate::common;

use common::{parse_json, parse_ndjson, path_text, run, run_success};

fn capture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures/quic-handshake.pcap")
}

fn capture_text() -> String {
    path_text(&capture()).to_owned()
}

#[test]
fn quic_reports_packet_counts_cids_and_version_negotiation() {
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "quic",
        &capture_text(),
    ]));
    assert_eq!(report["command"], "quic");
    assert_eq!(report["schema"], "packetcraftr.output/v18");
    let conversations = report["result"]["conversations"].as_array().unwrap();
    assert_eq!(conversations.len(), 1);
    let row = &conversations[0];
    assert_eq!(row["stream"], 0);
    assert_eq!(row["address_a"], "192.0.2.1");
    assert_eq!(row["port_a"], 63912);
    assert_eq!(row["address_b"], "198.51.100.2");
    assert_eq!(row["port_b"], 443);
    // The coalesced Initial + 1-RTT datagram counts one packet of each form.
    let packets = &row["packets"];
    assert_eq!(packets["initial"], 1);
    assert_eq!(packets["handshake"], 1);
    assert_eq!(packets["version_negotiation"], 1);
    assert_eq!(packets["one_rtt"], 3);
    assert_eq!(packets["malformed"], 1);
    assert_eq!(row["versions"], json!([1]));
    assert_eq!(row["negotiated"], json!([1, 0x6b33_4343]));
    assert_eq!(row["initial_dcid_hex"], "a1b2c3d4e5f60718");
    assert_eq!(row["initial_scid_hex"], "11223344");
    assert_eq!(row["duration"], json!({"secs": 6, "nanos": 0}));

    let summary = &report["result"]["summary"];
    assert_eq!(summary["conversations"], 1);
    assert_eq!(summary["quic_conversations"], 1);
    assert_eq!(summary["packets"], 6);
    assert_eq!(summary["malformed"], 1);
    assert_eq!(summary["non_quic_datagrams"], 1);
    assert_eq!(
        summary["first_malformed"],
        "truncated within the connection IDs"
    );
}

#[test]
fn quic_streams_conversations_then_a_complete_summary() {
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "analyze",
        "quic",
        &capture_text(),
    ]));
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["event"], "conversation");
    assert_eq!(records[0]["sequence"], 0);
    assert_eq!(records[0]["result"]["stream"], 0);
    assert_eq!(records[1]["event"], "complete");
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["result"]["packets"], 6);
}

#[test]
fn quic_text_renders_counts_and_summaries() {
    let rendered = run_success(&["analyze", "quic", &capture_text()]);
    let text = String::from_utf8_lossy(&rendered.stdout);
    assert!(
        text.contains(
            "packets 7 (initial 1 / zero_rtt 0 / handshake 1 / retry 0 / \
             version_negotiation 1 / one_rtt 3 / malformed 1)"
        ),
        "{text}"
    );
    assert!(text.contains("initial_dcid=a1b2c3d4e5f60718"), "{text}");
    assert!(
        text.contains("version_negotiation_offers=1,1798521667"),
        "{text}"
    );
    assert!(
        text.contains("quic conversations=1 quic_conversations=1 packets=6 malformed=1"),
        "{text}"
    );
    assert!(text.contains("first malformed packet: truncated within the connection IDs"));
}

#[test]
fn quic_selectors_and_service_ports_bound_the_report() {
    // The bundled capture has exactly one UDP conversation; selecting it
    // keeps the same row, while a tcp selector is refused.
    let selected = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "quic",
        &capture_text(),
        "--stream",
        "udp:0",
    ]));
    let conversations = selected["result"]["conversations"].as_array().unwrap();
    assert_eq!(conversations.len(), 1);
    assert_eq!(conversations[0]["packets"]["one_rtt"], 3);
    let refused = run(&["analyze", "quic", &capture_text(), "--stream", "tcp:0"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--stream udp:INDEX"),
        "{:?}",
        String::from_utf8_lossy(&refused.stderr)
    );

    // A capture without UDP 443 traffic reports zero conversations, and an
    // additional service port brings it back.
    let dns =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures/dns-response.pcap");
    let empty = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "quic",
        path_text(&dns),
    ]));
    assert_eq!(empty["result"]["conversations"], json!([]));
    assert_eq!(empty["result"]["summary"]["conversations"], 0);

    // Port zero is rejected at parse time.
    let bad_port = run(&["analyze", "quic", &capture_text(), "--quic-port", "0"]);
    assert_eq!(bad_port.status.code(), Some(2));
}

#[test]
fn quic_packet_ceilings_fail_the_pass_with_a_policy_error() {
    let output = run(&[
        "analyze",
        "quic",
        &capture_text(),
        "--max-quic-packets",
        "1",
    ]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("max_packets"),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = run(&[
        "analyze",
        "quic",
        &capture_text(),
        "--max-quic-conversations",
        "0",
    ]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
}
