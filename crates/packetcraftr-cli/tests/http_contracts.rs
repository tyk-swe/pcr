// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
#[path = "common/http_capture.rs"]
mod http_capture;
#[path = "common/process.rs"]
mod process_support;

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success};
use http_capture::{Capture, Stream};
use process_support::{append_truncated_record, run_with_stdin};
use serde_json::json;

fn at_ms(millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(millis)
}

/// A fresh single-stream capture on port 80 with its handshake at 0ms, 8ms,
/// and 16ms; the first data frame numbers 4.
fn opened_capture() -> (Capture, Stream) {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream, at_ms(0));
    (capture, stream)
}

/// The events an NDJSON run emitted, in order.
fn events(records: &[serde_json::Value]) -> Vec<&str> {
    records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect()
}

#[test]
fn http_command_reports_sourced_messages_without_retaining_entity_bodies() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "http", path]));
    let messages = document["result"]["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["start"]["method"], "GET");
    assert_eq!(messages[0]["start"]["target"], "/example");
    assert_eq!(messages[0]["sources"][0]["number"], 4);
    assert_eq!(messages[0]["sources"][1]["number"], 5);
    assert_eq!(messages[1]["request"], 1);
    assert_eq!(messages[1]["body_bytes"], 5);
    assert_eq!(messages[1]["trailers"][0]["value"], "yes");
    assert!(messages[1].get("body").is_none());
    // HT12: without --transactions the aggregate keeps an empty transaction
    // list and a null summary.
    assert_eq!(document["result"]["transactions"], json!([]));
    assert!(document["result"]["transaction_summary"].is_null());
    let records = parse_ndjson(&run_success(&["--output", "ndjson", "http", path]));
    assert_eq!(
        records
            .iter()
            .map(|row| row["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["http_message", "http_message", "complete"]
    );
    let limited = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--max-http-body-bytes",
        "4",
    ]));
    assert_eq!(limited["result"]["messages"][1]["status"], "limit");
    assert!(
        !run(&["--output", "json", "http", path, "--stream", "udp:0"])
            .status
            .success()
    );
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--max-application-output-bytes",
        "1",
    ]);
    assert!(!output.status.success());
    assert_eq!(parse_json(&output)["error"]["kind"], "policy");
}

#[test]
fn application_output_budget_counts_only_compact_event_payloads() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "http", path]));
    let total: usize = ["messages", "issues"]
        .iter()
        .flat_map(|key| document["result"][key].as_array().unwrap().iter())
        .map(|value| serde_json::to_vec(value).unwrap().len())
        .sum();
    let command = "http";
    let event_collections = [
        ("http_message", "messages"),
        ("http_stream_issue", "issues"),
    ];
    let expected_text = concat!(
        "HTTP tcp:0 message=1 status=complete GET /example body_bytes=0 request=none frames=4,5\n",
        "  Host: example.test\n",
        "  X-Test: one\n",
        "  X-Test: two\n",
        "HTTP tcp:0 message=2 status=complete 200 OK body_bytes=5 request=1 frames=6,7\n",
        "  Transfer-Encoding: chunked\n",
        "2 HTTP/1 messages, 2 complete, 0 incomplete, 0 malformed; 0 requests without a captured final response\n",
    );
    let error_message = "analysis consumer failed at frame 7";
    let error_cause = "application output exceeds --max-application-output-bytes";
    let exact = total.to_string();
    let under = (total - 1).to_string();
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
                assert_contiguous(&records);
                assert_eq!(records.last().unwrap()["event"], "complete");
                for &(event, key) in &event_collections {
                    let values = records
                        .iter()
                        .filter(|record| record["event"] == event)
                        .map(|record| record["result"].clone())
                        .collect();
                    assert_eq!(serde_json::Value::Array(values), document["result"][key]);
                }
            }
            "text" => assert_eq!(String::from_utf8(success.stdout).unwrap(), expected_text),
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
        assert_eq!(failure.status.code(), Some(6), "format {format}");
        let error = match format {
            "json" => parse_json(&failure)["error"].clone(),
            "ndjson" => {
                let records = parse_ndjson(&failure);
                assert_contiguous(&records);
                assert_eq!(records.last().unwrap()["event"], "error");
                assert_eq!(
                    records
                        .iter()
                        .filter(|record| record["event"] == "error")
                        .count(),
                    1
                );
                assert!(records.iter().all(|record| record["event"] != "complete"));
                records.last().unwrap()["error"].clone()
            }
            "text" => continue,
            _ => unreachable!(),
        };
        assert_eq!(error["code"], "policy.denied");
        assert_eq!(error["message"], error_message);
        assert_eq!(error["causes"][0], error_cause);
    }
}

#[test]
fn ndjson_budget_preserves_the_emitted_prefix_on_exhaustion() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let document = parse_json(&run_success(&["--output", "json", "http", path]));
    let first = serde_json::to_vec(&document["result"]["messages"][0])
        .unwrap()
        .len()
        .to_string();
    let output = run(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--max-application-output-bytes",
        &first,
    ]);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_eq!(
        records
            .iter()
            .map(|record| record["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["http_message", "error"]
    );
    assert_contiguous(&records);
    assert_eq!(records[0]["result"], document["result"]["messages"][0]);
    assert_eq!(records[1]["error"]["code"], "policy.denied");
    assert_eq!(
        records[1]["error"]["message"],
        "analysis consumer failed at frame 7"
    );
    assert_eq!(
        records[1]["error"]["causes"][0],
        "application output exceeds --max-application-output-bytes"
    );
}

// ---- --transactions publication (HTTP-T02) --------------------------------
//
// Every scenario builds its own capture: endpoints are RFC 5737 addresses
// and each frame's timestamp is chosen so availability markers and signed
// intervals assert exact values. Frame numbers are the 1-based write order
// and message indices are the invocation's parse-start order.

/// A request and a two-segment response whose head completes on the second
/// segment: one paired row.
fn paired_capture() -> Capture {
    let (mut capture, mut stream) = opened_capture();
    // The tab inside the header value exercises text escaping.
    capture.client(
        &mut stream,
        at_ms(4_000),
        b"GET / HTTP/1.1\r\nX-Test: a\tb\r\n\r\n",
    );
    capture.server(&mut stream, at_ms(4_125), b"HTTP/1.1 200");
    capture.server(
        &mut stream,
        at_ms(4_130),
        b" OK\r\nContent-Length: 0\r\n\r\n",
    );
    capture
}

#[test]
fn transactions_publish_a_paired_row_in_every_format() {
    let file = paired_capture().write();
    let path = path_text(file.path());
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--transactions",
    ]));
    // HT01: the row settles when the response head completes and records
    // the frames that made each boundary available.
    assert_eq!(
        document["result"]["transactions"],
        json!([{
            "index": 1,
            "stream": 0,
            "generation": 0,
            "flow": {
                "scope": 0,
                "flow": {
                    "source": "192.0.2.1",
                    "source_port": 40000,
                    "destination": "198.51.100.2",
                    "destination_port": 80
                }
            },
            "outcome": "paired",
            "request": 1,
            "response": 2,
            "response_status": 200,
            "informational": [],
            "request_headers_available": {
                "frame": 4,
                "timestamp": {"unix_seconds": 4, "nanoseconds": 0}
            },
            "response_started": {
                "frame": 5,
                "timestamp": {"unix_seconds": 4, "nanoseconds": 125_000_000}
            },
            "response_headers_available": {
                "frame": 6,
                "timestamp": {"unix_seconds": 4, "nanoseconds": 130_000_000}
            },
            "response_header_wait": {"nanoseconds": 125_000_000, "negative": false},
            "response_header_span": {"nanoseconds": 5_000_000, "negative": false}
        }])
    );
    assert_eq!(
        document["result"]["transaction_summary"],
        json!({
            "transactions": 1,
            "paired": 1,
            "unanswered": 0,
            "orphan_responses": 0,
            "negative_header_waits": 0,
            "negative_header_spans": 0
        })
    );
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
    ]));
    assert_contiguous(&records);
    assert_eq!(
        events(&records),
        [
            "http_message",
            "http_transaction",
            "http_message",
            "complete"
        ]
    );
    // The transaction precedes the response's own message record; its
    // `response` index is a forward reference into that record.
    assert_eq!(records[1]["result"], document["result"]["transactions"][0]);
    assert_eq!(records[0]["result"]["index"], 1);
    assert_eq!(records[2]["result"]["index"], 2);
    assert_eq!(
        records[1]["result"]["request"],
        records[0]["result"]["index"]
    );
    assert_eq!(
        records[1]["result"]["response"],
        records[2]["result"]["index"]
    );
    assert_eq!(
        records[3]["result"]["transaction_summary"],
        document["result"]["transaction_summary"]
    );
    let text = run_success(&["--output", "text", "http", path, "--transactions"]);
    assert_eq!(
        String::from_utf8(text.stdout).unwrap(),
        concat!(
            "HTTP tcp:0 message=1 status=complete GET / body_bytes=0 request=none frames=4\n",
            "  X-Test: a\\tb\n",
            "  transaction=1 outcome=paired stream=0 generation=0 request=1 response=2 status=200 wait=125000000ns span=5000000ns\n",
            "HTTP tcp:0 message=2 status=complete 200 OK body_bytes=0 request=1 frames=5,6\n",
            "  Content-Length: 0\n",
            "2 HTTP/1 messages, 2 complete, 0 incomplete, 0 malformed; 0 requests without a captured final response\n",
            "1 header transactions: 1 paired, 0 unanswered, 0 orphan responses; 0 negative waits, 0 negative spans\n",
        )
    );
}

#[test]
fn transactions_track_informational_responses_until_the_final_response() {
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, at_ms(4_100), b"HTTP/1.1 100 Continue\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_200),
        b"HTTP/1.1 103 Early Hints\r\n\r\n",
    );
    capture.server(
        &mut stream,
        at_ms(4_300),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    // HT02: interim 1xx heads emit their own message records but the row
    // stays open until the 200 settles it.
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
    ]));
    assert_contiguous(&records);
    assert_eq!(
        events(&records),
        [
            "http_message",
            "http_message",
            "http_message",
            "http_transaction",
            "http_message",
            "complete"
        ]
    );
    let transaction = &records[3]["result"];
    assert_eq!(transaction["outcome"], "paired");
    assert_eq!(transaction["request"], 1);
    assert_eq!(transaction["response"], 4);
    assert_eq!(transaction["response_status"], 200);
    assert_eq!(transaction["informational"], json!([2, 3]));
    assert_eq!(
        transaction["response_header_wait"],
        json!({"nanoseconds": 300_000_000, "negative": false})
    );
    assert_eq!(
        transaction["response_header_span"],
        json!({"nanoseconds": 0, "negative": false})
    );
    assert_eq!(transaction["response_started"]["frame"], 7);
    assert_eq!(transaction["response_headers_available"]["frame"], 7);
    for index in [2_usize, 3, 4] {
        assert_eq!(records[index - 1]["result"]["request"], 1, "record {index}");
    }
}

#[test]
fn transactions_mark_unsolicited_responses_orphans() {
    let (mut capture, mut stream) = opened_capture();
    capture.server(&mut stream, at_ms(4_000), b"HTTP/1.1 100 Continue\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    // HT03: each head without a pending request settles its own orphan row
    // on the response-direction flow.
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
    ]));
    assert_contiguous(&records);
    assert_eq!(
        events(&records),
        [
            "http_transaction",
            "http_message",
            "http_transaction",
            "http_message",
            "complete"
        ]
    );
    for (index, (status, response)) in [(100_u64, 1_u64), (200, 2)].into_iter().enumerate() {
        let transaction = &records[index * 2]["result"];
        assert_eq!(transaction["outcome"], "orphan_response");
        assert!(transaction["request"].is_null());
        assert_eq!(transaction["response"], response);
        assert_eq!(transaction["response_status"], status);
        assert!(transaction["request_headers_available"].is_null());
        assert!(transaction["response_header_wait"].is_null());
        // The head's own span still measures its two markers — zero here,
        // since one frame delivered the whole head.
        assert_eq!(
            transaction["response_header_span"],
            json!({"nanoseconds": 0, "negative": false})
        );
        assert_eq!(
            transaction["flow"]["flow"]["source_port"], 80,
            "orphan rows cite the response-direction flow"
        );
    }
    assert_eq!(records[0]["result"]["response_started"]["frame"], 4);
    assert_eq!(records[2]["result"]["response_started"]["frame"], 5);
    let summary = &records[4]["result"]["transaction_summary"];
    assert_eq!(summary["orphan_responses"], 2);
    assert_eq!(summary["transactions"], 2);
}

#[test]
fn transactions_pair_pipelined_requests_fifo_with_canonical_zero_intervals() {
    let (mut capture, mut stream) = opened_capture();
    capture.client(
        &mut stream,
        at_ms(10_000),
        b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
    );
    capture.server(
        &mut stream,
        at_ms(10_000),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    // HT04 + HT09: one frame delivers both heads; requests pair FIFO and
    // every marker on a shared frame is equal, so intervals are canonical
    // nonnegative zero.
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
    ]));
    assert_contiguous(&records);
    assert_eq!(
        events(&records),
        [
            "http_message",
            "http_message",
            "http_transaction",
            "http_message",
            "http_transaction",
            "http_message",
            "complete"
        ]
    );
    for (pair, request, response, status) in [(0_usize, 1_u64, 3_u64, 200_u64), (1, 2, 4, 204)] {
        let transaction = &records[2 + pair * 2]["result"];
        assert_eq!(transaction["outcome"], "paired");
        assert_eq!(transaction["request"], request);
        assert_eq!(transaction["response"], response);
        assert_eq!(transaction["response_status"], status);
        assert_eq!(transaction["request_headers_available"]["frame"], 4);
        assert_eq!(transaction["response_started"]["frame"], 5);
        assert_eq!(transaction["response_headers_available"]["frame"], 5);
        assert_eq!(
            transaction["response_header_wait"],
            json!({"nanoseconds": 0, "negative": false})
        );
        assert_eq!(
            transaction["response_header_span"],
            json!({"nanoseconds": 0, "negative": false})
        );
    }
}

#[test]
fn transaction_records_can_precede_the_message_records_they_cite() {
    let (mut capture, mut stream) = opened_capture();
    // The POST body stays open, so message 1 only resolves at end of input;
    // its transaction and the response's message record both precede it.
    capture.client(
        &mut stream,
        at_ms(4_000),
        b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc",
    );
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    // HT05/HT14 ordering: emission order is the settlement order, never the
    // index order of the records a row cites.
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
    ]));
    assert_contiguous(&records);
    assert_eq!(
        events(&records),
        [
            "http_transaction",
            "http_message",
            "http_message",
            "complete"
        ]
    );
    let transaction = &records[0]["result"];
    assert_eq!(transaction["outcome"], "paired");
    assert_eq!(transaction["request"], 1);
    assert_eq!(transaction["response"], 2);
    assert_eq!(records[1]["result"]["index"], 2);
    assert_eq!(records[2]["result"]["index"], 1);
    assert_eq!(records[2]["result"]["status"], "incomplete");
}

#[test]
fn transactions_settle_paired_rows_for_head_and_upgrades() {
    // HT06: the association tracks parsed heads; framing mode never changes
    // it, so HEAD, CONNECT tunnels, and 101 upgrades still pair.
    let head = {
        let (mut capture, mut stream) = opened_capture();
        capture.client(&mut stream, at_ms(4_000), b"HEAD /x HTTP/1.1\r\n\r\n");
        capture.server(
            &mut stream,
            at_ms(4_100),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        );
        capture.write()
    };
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path_text(head.path()),
        "--transactions",
    ]));
    assert_eq!(document["result"]["transactions"][0]["outcome"], "paired");
    assert_eq!(document["result"]["transactions"][0]["response"], 2);
    assert_eq!(document["result"]["messages"][0]["status"], "complete");
    assert_eq!(document["result"]["messages"][1]["status"], "complete");

    for (request, response_status, tunnel) in [
        (
            "CONNECT example.test:443 HTTP/1.1\r\n\r\n",
            "HTTP/1.1 200 Connected\r\n\r\n",
            "opaque-tunnel-bytes",
        ),
        (
            "GET /socket HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\n\r\n",
            "client-tunnel-bytes",
        ),
    ] {
        let (mut capture, mut stream) = opened_capture();
        capture.client(&mut stream, at_ms(4_000), request.as_bytes());
        capture.server(&mut stream, at_ms(4_100), response_status.as_bytes());
        capture.client(&mut stream, at_ms(4_200), tunnel.as_bytes());
        let file = capture.write();
        let document = parse_json(&run_success(&[
            "--output",
            "json",
            "http",
            path_text(file.path()),
            "--transactions",
        ]));
        let transactions = document["result"]["transactions"].as_array().unwrap();
        assert_eq!(transactions.len(), 1, "upgrade framing adds no rows");
        assert_eq!(transactions[0]["outcome"], "paired");
        assert_eq!(transactions[0]["request"], 1);
        assert_eq!(transactions[0]["response"], 2);
        assert_eq!(document["result"]["messages"][1]["status"], "upgrade");
        assert_eq!(document["result"]["summary"]["upgraded_connections"], 1);
    }
}

#[test]
fn transaction_markers_track_reassembly_not_delivery() {
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    // Bytes 4..8 arrive out of order on frame 5 and stay buffered; the
    // frame-6 fill releases bytes 0..8 together, and frame 7 completes the
    // head — so markers record the releasing frames, not delivery order.
    capture.server_beyond(&mut stream, 4, at_ms(5_000), &response[4..8]);
    capture.server_at(&mut stream, 5_000, at_ms(6_000), &response[..8]);
    stream.server_sequence += 8;
    capture.server(&mut stream, at_ms(7_000), &response[8..]);
    let file = capture.write();
    let path = path_text(file.path());
    // HT07: availability markers name the frames that released the bytes.
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--transactions",
    ]));
    let transaction = &document["result"]["transactions"][0];
    assert_eq!(transaction["outcome"], "paired");
    assert_eq!(transaction["response_started"]["frame"], 6);
    assert_eq!(transaction["response_headers_available"]["frame"], 7);
    assert_eq!(
        transaction["response_header_wait"],
        json!({"nanoseconds": 2_000_000_000, "negative": false})
    );
    assert_eq!(
        transaction["response_header_span"],
        json!({"nanoseconds": 1_000_000_000, "negative": false})
    );
    assert_eq!(
        document["result"]["messages"][1]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| source["number"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [5, 6, 7]
    );
}

#[test]
fn transaction_intervals_publish_signed_nanoseconds() {
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(10_000), b"GET / HTTP/1.1\r\n\r\n");
    // The capture clock regresses across the response's two segments.
    capture.server(&mut stream, at_ms(9_998), b"HTTP/1.1 200");
    capture.server(
        &mut stream,
        at_ms(9_997),
        b" OK\r\nContent-Length: 0\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    // HT08: negative deltas serialize with a separate sign flag in every
    // format and count in the summary.
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--transactions",
    ]));
    let transaction = &document["result"]["transactions"][0];
    assert_eq!(
        transaction["response_header_wait"],
        json!({"nanoseconds": 2_000_000, "negative": true})
    );
    assert_eq!(
        transaction["response_header_span"],
        json!({"nanoseconds": 1_000_000, "negative": true})
    );
    assert_eq!(transaction["response_started"]["frame"], 5);
    assert_eq!(transaction["response_headers_available"]["frame"], 6);
    assert_eq!(
        document["result"]["transaction_summary"],
        json!({
            "transactions": 1,
            "paired": 1,
            "unanswered": 0,
            "orphan_responses": 0,
            "negative_header_waits": 1,
            "negative_header_spans": 1
        })
    );
    let text = run_success(&["--output", "text", "http", path, "--transactions"]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.contains(
            "transaction=1 outcome=paired stream=0 generation=0 request=1 response=2 status=200 wait=-2000000ns span=-1000000ns"
        ),
        "{text}"
    );
}

/// Three conversations: the first is reused mid-capture (retiring its old
/// generation's pending request and pairing the new one), while the second
/// and third still hold pending requests at end of input.
fn reused_and_pending_capture() -> Capture {
    let mut capture = Capture::new();
    let mut first = Stream::new(40_000);
    let mut second = Stream::new(40_001);
    let mut third = Stream::new(40_002);
    capture.open(&mut first, at_ms(0));
    capture.open(&mut second, at_ms(1_000));
    capture.open(&mut third, at_ms(2_000));
    capture.client(&mut first, at_ms(3_000), b"GET /old HTTP/1.1\r\n\r\n");
    capture.reopen(&mut first, 10_000, at_ms(4_000));
    capture.client(&mut first, at_ms(4_100), b"GET /new HTTP/1.1\r\n\r\n");
    capture.server(
        &mut first,
        at_ms(4_200),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    capture.client(&mut third, at_ms(5_000), b"GET /pending-a HTTP/1.1\r\n\r\n");
    capture.client(
        &mut second,
        at_ms(6_000),
        b"GET /pending-b HTTP/1.1\r\n\r\n",
    );
    capture
}

#[test]
fn transactions_retire_generations_and_eof_pending_requests_in_request_index_order() {
    let file = reused_and_pending_capture().write();
    let path = path_text(file.path());
    // HT10: the reused stream's unanswered row precedes its new generation's
    // message; remaining pending requests retire at end of input in
    // ascending request index — request 4 (stream 2) before request 5
    // (stream 1), after every message record.
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
    ]));
    assert_contiguous(&records);
    assert_eq!(
        events(&records),
        [
            "http_message",
            "http_stream_issue",
            "http_stream_issue",
            "http_transaction",
            "http_message",
            "http_transaction",
            "http_message",
            "http_message",
            "http_message",
            "http_transaction",
            "http_transaction",
            "complete"
        ]
    );
    let transactions: Vec<&serde_json::Value> = records
        .iter()
        .filter(|record| record["event"] == "http_transaction")
        .map(|record| &record["result"])
        .collect();
    assert_eq!(
        transactions
            .iter()
            .map(|transaction| transaction["index"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert_eq!(transactions[0]["outcome"], "unanswered");
    assert_eq!(transactions[0]["request"], 1);
    assert_eq!(transactions[0]["stream"], 0);
    assert_eq!(transactions[0]["generation"], 0);
    assert_eq!(transactions[0]["request_headers_available"]["frame"], 10);
    assert!(transactions[0]["response"].is_null());
    assert_eq!(transactions[1]["outcome"], "paired");
    assert_eq!(transactions[1]["request"], 2);
    assert_eq!(transactions[1]["response"], 3);
    assert_eq!(transactions[1]["generation"], 1);
    assert_eq!(transactions[2]["outcome"], "unanswered");
    assert_eq!(transactions[2]["request"], 4);
    assert_eq!(transactions[2]["stream"], 2);
    assert_eq!(transactions[3]["outcome"], "unanswered");
    assert_eq!(transactions[3]["request"], 5);
    assert_eq!(transactions[3]["stream"], 1);
    // Both end-of-input rows follow the last message record.
    let last_message = records
        .iter()
        .rposition(|record| record["event"] == "http_message")
        .unwrap();
    let last_transaction = records
        .iter()
        .rposition(|record| record["event"] == "http_transaction")
        .unwrap();
    assert!(last_transaction > last_message);
    let summary = &records.last().unwrap()["result"]["transaction_summary"];
    assert_eq!(summary["transactions"], 4);
    assert_eq!(summary["unanswered"], 3);
    assert_eq!(summary["paired"], 1);
}

#[test]
fn transactions_associate_malformed_and_misframed_heads_by_parsed_boundary() {
    // HT11a: an unparseable start line never became a request, so the later
    // response is an orphan.
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"NOT-AN-HTTP-HEAD\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    let file = capture.write();
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path_text(file.path()),
        "--transactions",
    ]));
    assert_eq!(document["result"]["messages"][0]["status"], "malformed");
    let transactions = document["result"]["transactions"].as_array().unwrap();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0]["outcome"], "orphan_response");
    assert!(transactions[0]["request"].is_null());
    assert_eq!(transactions[0]["response"], 2);
    assert_eq!(document["result"]["messages"][1]["status"], "complete");

    // HT11b: a head that parsed before its body framing failed still
    // participates in the association.
    let (mut capture, mut stream) = opened_capture();
    capture.client(
        &mut stream,
        at_ms(4_000),
        b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    let file = capture.write();
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path_text(file.path()),
        "--transactions",
    ]));
    assert_eq!(document["result"]["messages"][0]["status"], "malformed");
    let transactions = document["result"]["transactions"].as_array().unwrap();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0]["outcome"], "paired");
    assert_eq!(transactions[0]["request"], 1);
    assert_eq!(transactions[0]["response"], 2);
    assert_eq!(document["result"]["messages"][1]["status"], "complete");
    assert_eq!(document["result"]["messages"][1]["request"], 1);
}

#[test]
fn transactions_stay_empty_disabled_and_report_zero_counts_when_empty() {
    let (capture, _stream) = opened_capture();
    let file = capture.write();
    let path = path_text(file.path());
    // Enabled on a conversation that never speaks HTTP: an explicit,
    // non-null all-zero summary.
    let enabled = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--transactions",
    ]));
    assert_eq!(enabled["result"]["transactions"], json!([]));
    assert_eq!(
        enabled["result"]["transaction_summary"],
        json!({
            "transactions": 0,
            "paired": 0,
            "unanswered": 0,
            "orphan_responses": 0,
            "negative_header_waits": 0,
            "negative_header_spans": 0
        })
    );
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
    ]));
    assert_eq!(events(&records), ["complete"]);
    assert_eq!(
        records[0]["result"]["transaction_summary"],
        enabled["result"]["transaction_summary"]
    );
    let text = run_success(&["--output", "text", "http", path, "--transactions"]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.contains(
            "0 header transactions: 0 paired, 0 unanswered, 0 orphan responses; 0 negative waits, 0 negative spans"
        ),
        "{text}"
    );
    // Disabled on the same capture: the v7 keys stay present but inert.
    let disabled = parse_json(&run_success(&["--output", "json", "http", path]));
    assert_eq!(disabled["result"]["transactions"], json!([]));
    assert!(disabled["result"]["transaction_summary"].is_null());
    let text = run_success(&["--output", "text", "http", path]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(!text.contains("header transactions"), "{text}");
}

#[test]
fn transactions_respect_stream_selection_and_epoch_bounds() {
    // --stream narrows the run to one capture-global stream while message
    // and transaction indices stay invocation-local.
    let file = reused_and_pending_capture().write();
    let path = path_text(file.path());
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--stream",
        "tcp:1",
        "--transactions",
    ]));
    assert_eq!(document["result"]["messages"].as_array().unwrap().len(), 1);
    assert_eq!(document["result"]["messages"][0]["index"], 1);
    assert_eq!(document["result"]["messages"][0]["stream"], 1);
    let transactions = document["result"]["transactions"].as_array().unwrap();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0]["outcome"], "unanswered");
    assert_eq!(transactions[0]["request"], 1);
    assert_eq!(transactions[0]["stream"], 1);
    assert_eq!(transactions[0]["generation"], 0);

    // Epoch bounds scope which frames reached the collector: a request
    // whose responses were filtered out retires unanswered, and a response
    // seen without its request is an orphan.
    let file = paired_capture().write();
    let path = path_text(file.path());
    let stopped = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--transactions",
        "--stop-epoch",
        "4.05",
    ]));
    let transactions = stopped["result"]["transactions"].as_array().unwrap();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0]["outcome"], "unanswered");
    assert_eq!(transactions[0]["request"], 1);
    assert!(transactions[0]["response"].is_null());
    assert!(transactions[0]["response_header_wait"].is_null());
    assert_eq!(transactions[0]["request_headers_available"]["frame"], 4);
    // Text prints `none` for every absent identifier and interval.
    let text = run_success(&[
        "--output",
        "text",
        "http",
        path,
        "--transactions",
        "--stop-epoch",
        "4.05",
    ]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.contains(
            "transaction=1 outcome=unanswered stream=0 generation=0 request=1 response=none status=none wait=none span=none"
        ),
        "{text}"
    );
    let started = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--transactions",
        "--start-epoch",
        "4.05",
    ]));
    let transactions = started["result"]["transactions"].as_array().unwrap();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0]["outcome"], "orphan_response");
    assert!(transactions[0]["request"].is_null());
    assert_eq!(transactions[0]["response"], 1);
    assert_eq!(transactions[0]["response_started"]["frame"], 5);
    assert_eq!(transactions[0]["response_headers_available"]["frame"], 6);
}

#[test]
fn application_output_budget_charges_transaction_records_exactly() {
    let file = paired_capture().write();
    let path = path_text(file.path());
    // HT13: serialized transaction bytes draw from the same
    // --max-application-output-bytes allowance as message records.
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--transactions",
    ]));
    let total: usize = ["messages", "transactions", "issues"]
        .iter()
        .flat_map(|key| document["result"][key].as_array().unwrap().iter())
        .map(|value| serde_json::to_vec(value).unwrap().len())
        .sum();
    let exact = total.to_string();
    let under = (total - 1).to_string();
    for format in ["json", "ndjson", "text"] {
        let success = run_success(&[
            "--output",
            format,
            "http",
            path,
            "--transactions",
            "--max-application-output-bytes",
            &exact,
        ]);
        if format == "ndjson" {
            let records = parse_ndjson(&success);
            assert_contiguous(&records);
            assert_eq!(records.last().unwrap()["event"], "complete");
        }
        let failure = run(&[
            "--output",
            format,
            "http",
            path,
            "--transactions",
            "--max-application-output-bytes",
            &under,
        ]);
        assert_eq!(failure.status.code(), Some(6), "format {format}");
        if format == "ndjson" {
            let records = parse_ndjson(&failure);
            assert_eq!(records.last().unwrap()["event"], "error");
            assert_eq!(records.last().unwrap()["error"]["code"], "policy.denied");
        }
    }
    // An allowance covering the first message and the transaction leaves
    // that emitted prefix intact when the next record overflows it.
    let allowance = serde_json::to_vec(&document["result"]["messages"][0])
        .unwrap()
        .len()
        + serde_json::to_vec(&document["result"]["transactions"][0])
            .unwrap()
            .len();
    let output = run(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
        "--max-application-output-bytes",
        &allowance.to_string(),
    ]);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_eq!(
        events(&records),
        ["http_message", "http_transaction", "error"]
    );
    assert_contiguous(&records);
    assert_eq!(records[0]["result"], document["result"]["messages"][0]);
    assert_eq!(records[1]["result"], document["result"]["transactions"][0]);
    assert_eq!(records[2]["error"]["code"], "policy.denied");
}

#[test]
fn retained_byte_allowance_failure_reports_a_classified_policy_error() {
    let file = paired_capture().write();
    let path = path_text(file.path());
    // HT13: the retained-byte charge for the pending request fails before
    // any evidence publishes; the failure is classified, not silent.
    let output = run(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--transactions",
        "--max-application-retained-bytes",
        "5000",
    ]);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_eq!(events(&records), ["error"]);
    assert_eq!(records[0]["error"]["code"], "policy.application_limit");
}

#[cfg(packetcraftr_test_dev_full)]
#[test]
fn broken_stdout_reports_an_incomplete_ndjson_stream() {
    // HT14: a failed emit stops the run; the stream reports one terminal
    // diagnostic instead of a complete record.
    common::require_dev_full();
    let file = paired_capture().write();
    let path = path_text(file.path()).to_owned();
    let failure = std::process::Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(["--output", "ndjson", "http", &path, "--transactions"])
        .stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full must be writable for the write-failure contract"),
        )
        .output()
        .expect("CLI process must start");
    assert_eq!(failure.status.code(), Some(5), "{failure:?}");
    let stderr = String::from_utf8(failure.stderr).expect("stderr is UTF-8");
    // The first emit already fails, the run reports one classified
    // `io.stdout` chain — the frame where the stream broke plus the write
    // failure — and the stream ends incomplete rather than complete.
    assert!(stderr.starts_with("error[io.stdout]: "), "{stderr}");
    assert!(stderr.contains("NDJSON stream is incomplete"), "{stderr}");
    assert!(
        stderr.contains("analysis consumer failed at frame 4"),
        "{stderr}"
    );
}

#[test]
fn transactions_read_compressed_and_standard_input_sources() {
    use std::io::Write as _;

    use packetcraftr_core::capture_file::compression;

    let bytes = paired_capture().bytes();
    // The same capture through gzip and Zstd decoders must publish the
    // identical transaction evidence.
    for format in [compression::Format::Gzip, compression::Format::Zstd] {
        let mut encoder =
            compression::Output::new(Vec::new(), format).expect("compressor must open");
        encoder
            .write_all(&bytes)
            .expect("compression must accept bytes");
        let compressed = encoder.finish().expect("compressed stream must finish");
        let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
        file.write_all(&compressed)
            .expect("compressed capture must write");
        file.flush().expect("compressed capture must flush");
        let document = parse_json(&run_success(&[
            "--output",
            "json",
            "http",
            path_text(file.path()),
            "--transactions",
        ]));
        assert_eq!(
            document["result"]["transactions"].as_array().unwrap().len(),
            1
        );
        assert_eq!(document["result"]["transactions"][0]["outcome"], "paired");
        assert_eq!(document["result"]["transaction_summary"]["transactions"], 1);
    }
    // Stdin carries the same bytes to the same result.
    let file_capture = paired_capture().write();
    let file_document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path_text(file_capture.path()),
        "--transactions",
    ]));
    let stdin = run_with_stdin(&["--output", "json", "http", "-", "--transactions"], &bytes);
    let stdin_document = parse_json(&stdin);
    assert_eq!(stdin_document["result"], file_document["result"]);
    assert_eq!(
        stdin_document["result"]["transactions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

// ---- --body-message/--write artifact publication (HTTP-B02) -----------------
//
// The staged artifact publishes the selected message's entity bytes —
// Content-Length, close-delimited, or concatenated chunk data with every
// content and remaining transfer coding kept — only after the whole capture
// inspects cleanly and the message is terminally complete. Every failure path
// must leave neither the destination nor staged residue, so assertions read
// the staging directory itself rather than only the destination path.

/// The lowercase hex SHA-256 `body_export.sha256` publishes.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut digest, byte| {
            let _ = write!(digest, "{byte:02x}");
            digest
        })
}

/// Nothing may remain in the staging directory — no destination and no
/// abandoned temporary file — after a run that must not publish.
fn assert_staging_empty(directory: &Path) {
    let residue: Vec<_> = std::fs::read_dir(directory)
        .expect("staging directory must list")
        .collect::<Result<_, _>>()
        .expect("staging entries must read");
    assert!(residue.is_empty(), "artifact residue remains: {residue:?}");
}

/// The `error` object of a failed run's JSON envelope.
fn failure(output: &std::process::Output) -> serde_json::Value {
    assert!(!output.status.success(), "expected failure: {output:?}");
    parse_json(output)["error"].clone()
}

#[test]
fn body_export_publishes_the_exact_selected_bytes_in_every_format() {
    // HB01: the binary entity — NUL and non-UTF-8 bytes included — spans
    // three segments and publishes byte-exact; the digest covers exactly the
    // accepted bytes.
    let body = b"\x00\x1f\x8b\x08\xff\xfepacketcraftr-body\x00\x80\x81tail".to_vec();
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET /object HTTP/1.1\r\n\r\n");
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    capture.server(&mut stream, at_ms(4_100), head.as_bytes());
    capture.server(&mut stream, at_ms(4_200), &body[..8]);
    capture.server(&mut stream, at_ms(4_300), &body[8..19]);
    capture.server(&mut stream, at_ms(4_400), &body[19..]);
    let file = capture.write();
    let path = path_text(file.path());
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("body.bin");
    let digest = sha256_hex(&body);

    // Aggregate JSON publishes the record; the file's bytes and the DTO's
    // digest agree exactly.
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]));
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    assert_eq!(
        document["result"]["body_export"],
        json!({
            "message": 2,
            "stream": 0,
            "generation": 0,
            "path": path_text(&destination),
            "bytes": body.len() as u64,
            "sha256": digest,
            "representation": "http_body_after_dechunking",
        })
    );
    assert_eq!(
        document["result"]["messages"][1]["body_bytes"],
        body.len() as u64
    );
    // Body bytes themselves never embed in machine output.
    assert!(document["result"]["messages"][1].get("body").is_none());
    // Without a selection the v7 key stays present and null.
    let plain = parse_json(&run_success(&["--output", "json", "http", path]));
    assert!(plain["result"]["body_export"].is_null());

    // HB11: the committed destination is never overwritten — a second export
    // to it fails without touching the published bytes.
    let rerun = run(&[
        "--output",
        "json",
        "http",
        path,
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]);
    assert_eq!(rerun.status.code(), Some(5));
    assert_eq!(failure(&rerun)["code"], "io.output_file");
    assert_eq!(std::fs::read(&destination).unwrap(), body);

    // HB16: NDJSON emits only the ordinary message events plus the terminal
    // complete record that carries the artifact record — there is no
    // artifact event before `complete`.
    let ndjson_destination = directory.path().join("body-ndjson.bin");
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "http",
        path,
        "--body-message",
        "2",
        "--write",
        path_text(&ndjson_destination),
    ]));
    assert_eq!(std::fs::read(&ndjson_destination).unwrap(), body);
    assert_contiguous(&records);
    assert_eq!(
        events(&records),
        ["http_message", "http_message", "complete"]
    );
    let export = &records[2]["result"]["body_export"];
    assert_eq!(export["message"], 2);
    assert_eq!(export["stream"], 0);
    assert_eq!(export["generation"], 0);
    assert_eq!(export["bytes"], body.len() as u64);
    assert_eq!(export["sha256"], digest);
    assert_eq!(export["representation"], "http_body_after_dechunking");
    assert_eq!(export["path"], path_text(&ndjson_destination));

    // Text keeps the message rows and adds the artifact line before the
    // normal summary.
    let text_destination = directory.path().join("body-text.bin");
    let text = run_success(&[
        "--output",
        "text",
        "http",
        path,
        "--body-message",
        "2",
        "--write",
        path_text(&text_destination),
    ]);
    assert_eq!(std::fs::read(&text_destination).unwrap(), body);
    let stdout = String::from_utf8(text.stdout).unwrap();
    let artifact_line = format!(
        "body message=2 bytes={} sha256={digest} path={}\n",
        body.len(),
        path_text(&text_destination)
    );
    assert!(stdout.contains(&artifact_line), "{stdout}");
    let artifact_at = stdout.find(&artifact_line).unwrap();
    let summary_at = stdout.find("2 HTTP/1 messages").unwrap();
    assert!(artifact_at < summary_at, "{stdout}");

    // --transactions composes with the export: the row publishes and the
    // artifact is identical.
    let transactions_destination = directory.path().join("body-transactions.bin");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--transactions",
        "--body-message",
        "2",
        "--write",
        path_text(&transactions_destination),
    ]));
    assert_eq!(std::fs::read(&transactions_destination).unwrap(), body);
    assert_eq!(
        document["result"]["transactions"].as_array().unwrap().len(),
        1
    );
    assert_eq!(document["result"]["body_export"]["sha256"], digest);
}

#[test]
fn body_export_writes_only_concatenated_chunk_data() {
    // HB02: chunk sizes, extensions, and CRLF framing split mid-token across
    // segments never reach the artifact; trailers and the pipelined next
    // message's bytes stay out too.
    let (mut capture, mut stream) = opened_capture();
    capture.client(
        &mut stream,
        at_ms(4_000),
        b"POST /a HTTP/1.1\r\nContent-Length: 0\r\n\r\nPOST /b HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    );
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ex",
    );
    capture.server(&mut stream, at_ms(4_200), b"t=\"ok\"\r\nab");
    capture.server(
        &mut stream,
        at_ms(4_300),
        b"c\r\n2;x\r\nde\r\n0\r\nX-End: yes\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("chunks.bin");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--body-message",
        "3",
        "--write",
        path_text(&destination),
    ]));
    assert_eq!(std::fs::read(&destination).unwrap(), b"abcde");
    assert_eq!(document["result"]["body_export"]["bytes"], 5);
    assert_eq!(
        document["result"]["body_export"]["sha256"],
        sha256_hex(b"abcde")
    );
    // The pipelined 204 is a separate message 4; only message 3's chunk data
    // shipped.
    assert_eq!(document["result"]["messages"].as_array().unwrap().len(), 4);
    assert_eq!(document["result"]["messages"][3]["status"], "complete");
}

#[test]
fn body_export_preserves_coded_bytes_without_decoding() {
    // HB03: Content-Encoding bytes publish exactly — the artifact may hold
    // gzip-coded data, never decompressed — and a remaining non-final
    // transfer coding passes through just as it rode the wire.
    let coded: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x03\x00tail!";
    let (mut capture, mut stream) = opened_capture();
    capture.client(
        &mut stream,
        at_ms(4_000),
        b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        coded.len()
    );
    capture.server(&mut stream, at_ms(4_100), head.as_bytes());
    capture.server(&mut stream, at_ms(4_200), &coded[..7]);
    capture.server(&mut stream, at_ms(4_300), &coded[7..]);
    capture.server(
        &mut stream,
        at_ms(4_400),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\nWXYZ\r\n0\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    let directory = tempfile::tempdir().expect("staging dir");

    // Message 3's Content-Length bytes land verbatim, gzip magic included.
    let coded_destination = directory.path().join("coded.bin");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--body-message",
        "3",
        "--write",
        path_text(&coded_destination),
    ]));
    assert_eq!(std::fs::read(&coded_destination).unwrap(), coded);
    assert_eq!(
        document["result"]["body_export"]["bytes"],
        coded.len() as u64
    );
    assert_eq!(
        document["result"]["body_export"]["representation"],
        "http_body_after_dechunking"
    );

    // Message 4 removes only the chunk framing; the gzip transfer coding
    // remains exactly as transmitted.
    let transfer_destination = directory.path().join("transfer.bin");
    parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--body-message",
        "4",
        "--write",
        path_text(&transfer_destination),
    ]));
    assert_eq!(std::fs::read(&transfer_destination).unwrap(), b"WXYZ");
}

#[test]
fn body_export_of_a_close_delimited_body_requires_a_clean_close() {
    // HB04: only a clean FIN completes a close-delimited body; EOF alone and
    // a reset leave the message non-complete and publish nothing.
    let build = |ending: u8| {
        let (mut capture, mut stream) = opened_capture();
        capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.0\r\n\r\n");
        capture.server(&mut stream, at_ms(4_100), b"HTTP/1.0 200 OK\r\n\r\nbo");
        capture.server(&mut stream, at_ms(4_200), b"dy");
        match ending {
            0 => capture.server_close(&mut stream, at_ms(4_300)),
            1 => capture.server_reset(&mut stream, at_ms(4_300)),
            _ => {}
        }
        capture
    };

    let file = build(0).write();
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("closed.bin");
    parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path_text(file.path()),
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]));
    assert_eq!(std::fs::read(&destination).unwrap(), b"body");

    for (ending, status) in [(1_u8, "evicted"), (2_u8, "incomplete")] {
        let file = build(ending).write();
        let directory = tempfile::tempdir().expect("staging dir");
        let destination = directory.path().join("unclosed.bin");
        let output = run(&[
            "--output",
            "json",
            "http",
            path_text(file.path()),
            "--body-message",
            "2",
            "--write",
            path_text(&destination),
        ]);
        assert_eq!(output.status.code(), Some(3), "ending {ending}");
        let error = failure(&output);
        assert_eq!(error["code"], "packet.http_body_incomplete");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains(&format!("status {status}")),
            "ending {ending}: {error}"
        );
        assert_staging_empty(directory.path());
    }
}

#[test]
fn body_export_empty_bodies_publish_and_upgrades_do_not() {
    // HB05: a terminally complete empty body publishes an empty file;
    // CONNECT/101 upgrades have no exportable body.
    let (mut capture, mut stream) = opened_capture();
    capture.client(
        &mut stream,
        at_ms(4_000),
        b"GET /a HTTP/1.1\r\n\r\nHEAD /b HTTP/1.1\r\n\r\nGET /c HTTP/1.1\r\n\r\nGET /d HTTP/1.1\r\n\r\n",
    );
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    // The HEAD response declares a Content-Length the request forbids it
    // from carrying.
    capture.server(
        &mut stream,
        at_ms(4_200),
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n",
    );
    capture.server(
        &mut stream,
        at_ms(4_300),
        b"HTTP/1.1 204 No Content\r\n\r\n",
    );
    capture.server(
        &mut stream,
        at_ms(4_400),
        b"HTTP/1.1 304 Not Modified\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    let empty = sha256_hex(b"");
    for (index, name) in [
        (5_u8, "empty-cl.bin"),
        (6, "head.bin"),
        (7, "no-content.bin"),
        (8, "not-modified.bin"),
    ] {
        let directory = tempfile::tempdir().expect("staging dir");
        let destination = directory.path().join(name);
        let index = index.to_string();
        let document = parse_json(&run_success(&[
            "--output",
            "json",
            "http",
            path,
            "--body-message",
            &index,
            "--write",
            path_text(&destination),
        ]));
        assert_eq!(std::fs::read(&destination).unwrap(), b"", "message {index}");
        assert_eq!(document["result"]["body_export"]["bytes"], 0);
        assert_eq!(document["result"]["body_export"]["sha256"], empty);
    }

    for (request, response) in [
        (
            "CONNECT example.test:443 HTTP/1.1\r\n\r\n",
            "HTTP/1.1 200 Connected\r\n\r\n",
        ),
        (
            "GET /socket HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\n\r\n",
        ),
    ] {
        let (mut capture, mut stream) = opened_capture();
        capture.client(&mut stream, at_ms(4_000), request.as_bytes());
        capture.server(&mut stream, at_ms(4_100), response.as_bytes());
        capture.client(&mut stream, at_ms(4_200), b"tunnel-bytes");
        let file = capture.write();
        let directory = tempfile::tempdir().expect("staging dir");
        let destination = directory.path().join("tunnel.bin");
        let output = run(&[
            "--output",
            "json",
            "http",
            path_text(file.path()),
            "--body-message",
            "2",
            "--write",
            path_text(&destination),
        ]);
        assert_eq!(output.status.code(), Some(3), "{request}");
        let error = failure(&output);
        assert_eq!(error["code"], "packet.http_body_incomplete");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("status upgrade"),
            "{request}: {error}"
        );
        assert_staging_empty(directory.path());
    }
}

#[test]
fn body_export_reassembles_each_body_byte_exactly_once() {
    // HB06: an exact retransmission and an out-of-order span filled later
    // deliver each byte once under the configured overlap semantics — the
    // artifact equals the offered body with no duplicated bytes.
    let body = b"0123456789abcdef";
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    capture.server(&mut stream, at_ms(4_100), head.as_bytes());
    let sequence = stream.server_sequence;
    capture.server(&mut stream, at_ms(4_200), &body[..4]);
    // Identical retransmission of the first span: accepted once.
    capture.server_at(&mut stream, sequence, at_ms(4_300), &body[..4]);
    // Bytes 8..16 land four ahead of the stream; the 4..8 fill then releases
    // the whole buffered tail exactly once.
    capture.server_beyond(&mut stream, 4, at_ms(4_400), &body[8..]);
    capture.server(&mut stream, at_ms(4_500), &body[4..8]);
    let file = capture.write();
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("reassembled.bin");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path_text(file.path()),
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]));
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    assert_eq!(
        document["result"]["body_export"]["bytes"],
        body.len() as u64
    );
    assert_eq!(
        document["result"]["body_export"]["sha256"],
        sha256_hex(body)
    );
}

#[test]
fn body_selection_arguments_fail_as_usage_without_staging() {
    // HB07 + HB17: pairing and value errors keep Clap's ordinary usage
    // failure; the destination never stages.
    let file = paired_capture().write();
    let path = path_text(file.path());
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("body.bin");
    let write = path_text(&destination);
    for arguments in [
        vec!["http", path, "--body-message", "2"],
        vec!["http", path, "--write", write],
        vec!["http", path, "--body-message", "0", "--write", write],
        vec!["http", path, "--body-message", "nope", "--write", write],
        vec![
            "http",
            path,
            "--body-message",
            "18446744073709551616",
            "--write",
            write,
        ],
        vec![
            "http",
            path,
            "--body-message",
            "2",
            "--body-message",
            "3",
            "--write",
            write,
        ],
        vec![
            "http",
            path,
            "--body-message",
            "2",
            "--write",
            write,
            "--write",
            "other.bin",
        ],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert_staging_empty(directory.path());
    }
}

#[test]
fn body_selection_numbers_messages_within_this_invocation() {
    // HB07: the index is this invocation's one-based parse-start order,
    // narrowed by --stream — not a TCP stream index, frame number, or
    // capture-global identifier.
    let mut capture = Capture::new();
    let mut first = Stream::new(40_000);
    let mut second = Stream::new(40_001);
    capture.open(&mut first, at_ms(0));
    capture.open(&mut second, at_ms(1_000));
    capture.client(&mut second, at_ms(2_000), b"GET /b HTTP/1.1\r\n\r\n");
    capture.server(
        &mut second,
        at_ms(2_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz",
    );
    capture.client(&mut first, at_ms(3_000), b"GET /a HTTP/1.1\r\n\r\n");
    capture.server(
        &mut first,
        at_ms(3_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    let directory = tempfile::tempdir().expect("staging dir");
    // Under --stream tcp:1 the second conversation's response is message 2
    // in this invocation even though stream 0's messages came later in the
    // capture.
    let destination = directory.path().join("b.bin");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--stream",
        "tcp:1",
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]));
    assert_eq!(std::fs::read(&destination).unwrap(), b"xyz");
    assert_eq!(document["result"]["body_export"]["stream"], 1);
    assert_eq!(document["result"]["body_export"]["generation"], 0);

    // A capture-global index that does not exist inside the narrowed
    // invocation is a usage failure, and staging cleans itself up.
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("unobserved.bin");
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--stream",
        "tcp:1",
        "--body-message",
        "3",
        "--write",
        path_text(&destination),
    ]);
    assert_eq!(output.status.code(), Some(2));
    let error = failure(&output);
    assert_eq!(error["code"], "cli.http_body_message");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("message 3 was not observed"),
        "{error}"
    );
    assert_staging_empty(directory.path());

    // A pre-existing --stream selection error takes precedence over the
    // absent body message.
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("bad-stream.bin");
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--stream",
        "udp:0",
        "--body-message",
        "9",
        "--write",
        path_text(&destination),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        failure(&output)["message"]
            .as_str()
            .unwrap()
            .contains("--stream tcp:INDEX"),
        "{output:?}"
    );
    assert_staging_empty(directory.path());
}

#[test]
fn body_export_terminal_status_failures_publish_nothing() {
    // HB08: every non-complete terminal status fails with the failure
    // table's classification and leaves no partial artifact behind.
    let (mut capture, mut stream) = opened_capture();
    capture.client(
        &mut stream,
        at_ms(4_000),
        b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nabcde",
    );
    let malformed = capture.write();

    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc",
    );
    let incomplete = capture.write();

    // A contradictory retransmission of already-delivered bytes stops the
    // selected message at conflict.
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nabcd",
    );
    let sequence = stream.server_sequence;
    capture.server_at(&mut stream, sequence - 4, at_ms(4_200), b"abXX");
    let conflict = capture.write();

    // A permanently unfilled hole stops the selected message at gap when the
    // flow's eviction reports it.
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nab",
    );
    capture.server_beyond(&mut stream, 20, at_ms(4_200), b"far-away");
    capture.server_reset(&mut stream, at_ms(4_300));
    let gap = capture.write();

    // A mid-body RST without a hole evicts the live message.
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nab",
    );
    capture.server_reset(&mut stream, at_ms(4_200));
    let evicted = capture.write();

    for (file, index, status, http_cause) in [
        (
            &malformed,
            "1",
            "malformed",
            Some("has both Transfer-Encoding and Content-Length"),
        ),
        (&incomplete, "2", "incomplete", None),
        (&conflict, "2", "conflict", None),
        (&gap, "2", "gap", None),
        (&evicted, "2", "evicted", None),
    ] {
        let directory = tempfile::tempdir().expect("staging dir");
        let destination = directory.path().join("body.bin");
        let output = run(&[
            "--output",
            "json",
            "http",
            path_text(file.path()),
            "--body-message",
            index,
            "--write",
            path_text(&destination),
        ]);
        assert_eq!(output.status.code(), Some(3), "{status}: {output:?}");
        let error = failure(&output);
        assert_eq!(error["code"], "packet.http_body_incomplete", "{status}");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains(&format!("message {index} ended with status {status}")),
            "{status}: {error}"
        );
        // The original HTTP parse cause rides in the chain when the status
        // carries one.
        if let Some(http_cause) = http_cause {
            assert!(
                error["causes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|cause| cause.as_str().unwrap().contains(http_cause)),
                "{status}: {error}"
            );
        }
        assert_staging_empty(directory.path());
    }
}

#[test]
fn body_export_never_publishes_after_a_late_capture_failure() {
    use packetcraftr_core::capture_file::compression;
    use std::io::Write as _;

    // HB09: a read or decompression failure anywhere in the capture — even
    // after the selected body completed — blocks publication entirely.
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );

    // Garbage after the last good record fails the capture read.
    let mut truncated = capture.write();
    append_truncated_record(&mut truncated);
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("body.bin");
    let output = run(&[
        "--output",
        "json",
        "http",
        path_text(truncated.path()),
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(failure(&output)["code"], "packet.capture_file");
    assert_staging_empty(directory.path());

    // A compressed stream missing its tail fails the whole read as well.
    let mut encoder =
        compression::Output::new(Vec::new(), compression::Format::Gzip).expect("compressor");
    encoder
        .write_all(&capture.bytes())
        .expect("compression accepts bytes");
    let mut compressed = encoder.finish().expect("compressed stream finishes");
    compressed.truncate(compressed.len() - 8);
    let mut file = tempfile::NamedTempFile::new().expect("compressed capture");
    file.write_all(&compressed)
        .expect("compressed capture writes");
    file.flush().expect("compressed capture flushes");
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("body.bin");
    let output = run(&[
        "--output",
        "json",
        "http",
        path_text(file.path()),
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(failure(&output)["code"], "io.capture_compression");
    assert_staging_empty(directory.path());
}

#[test]
fn body_export_publishes_despite_later_ordinary_issues() {
    // HB10: a later malformed message or stream issue on another flow is
    // ordinary inspection evidence, not an execution failure — the selected
    // artifact still publishes.
    let mut capture = Capture::new();
    let mut first = Stream::new(40_000);
    let mut second = Stream::new(40_001);
    capture.open(&mut first, at_ms(0));
    capture.client(&mut first, at_ms(1_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut first,
        at_ms(1_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );
    capture.open(&mut second, at_ms(2_000));
    capture.client(&mut second, at_ms(2_100), b"NOT-AN-HTTP-HEAD\r\n\r\n");
    capture.server_reset(&mut second, at_ms(2_200));
    let file = capture.write();
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("body.bin");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path_text(file.path()),
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]));
    assert_eq!(std::fs::read(&destination).unwrap(), b"hello");
    assert_eq!(document["result"]["messages"][2]["status"], "malformed");
    assert!(
        document["result"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["status"] == "evicted"),
        "{document}"
    );
    assert_eq!(document["result"]["body_export"]["bytes"], 5);
    assert_eq!(
        document["result"]["body_export"]["sha256"],
        sha256_hex(b"hello")
    );
}

#[test]
fn body_export_never_clobbers_an_existing_destination() {
    // HB11: an existing file, a dangling symlink, and an absent parent each
    // fail before input is read; nothing stages and nothing is overwritten.
    let file = paired_capture().write();
    let path = path_text(file.path());
    let directory = tempfile::tempdir().expect("staging dir");

    let occupied = directory.path().join("occupied.bin");
    std::fs::write(&occupied, b"mine").expect("occupying file writes");
    // The second case names the capture input itself: it is a file too and
    // must not be clobbered.
    for destination in [path_text(&occupied).to_owned(), path.to_owned()] {
        let output = run(&[
            "--output",
            "json",
            "http",
            path,
            "--body-message",
            "2",
            "--write",
            destination.as_str(),
        ]);
        assert_eq!(output.status.code(), Some(5), "{destination}");
        let error = failure(&output);
        assert_eq!(error["code"], "io.output_file");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("already exists")
        );
    }
    assert_eq!(std::fs::read(&occupied).unwrap(), b"mine");
    assert!(std::fs::metadata(file.path()).unwrap().len() > 0);

    #[cfg(unix)]
    {
        let dangling = directory.path().join("dangling.bin");
        std::os::unix::fs::symlink("missing-target", &dangling).expect("dangling symlink");
        let output = run(&[
            "--output",
            "json",
            "http",
            path,
            "--body-message",
            "2",
            "--write",
            path_text(&dangling),
        ]);
        assert_eq!(output.status.code(), Some(5));
        assert_eq!(failure(&output)["code"], "io.output_file");
        assert!(std::fs::symlink_metadata(&dangling).unwrap().is_symlink());
    }

    // An absent parent is an I/O failure at staging, not a parse error; no
    // destination directory is invented.
    let missing = directory.path().join("absent-parent").join("body.bin");
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--body-message",
        "2",
        "--write",
        path_text(&missing),
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(failure(&output)["code"], "io.output_file");
    assert!(!missing.parent().unwrap().exists());
}

#[test]
fn body_export_limit_and_metadata_budget_failures_publish_nothing() {
    // HB13a: one byte beyond --max-http-body-bytes ends the message at the
    // limit; no beyond-limit byte ever reached the sink, nothing publishes,
    // and the limit keeps its policy classification and HTTP cause.
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );
    let file = capture.write();
    let path = path_text(file.path());
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("limited.bin");
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--max-http-body-bytes",
        "4",
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]);
    assert_eq!(output.status.code(), Some(6));
    let error = failure(&output);
    assert_eq!(error["code"], "policy.http_limit");
    assert!(
        error["message"].as_str().unwrap().contains("status limit"),
        "{error}"
    );
    assert!(
        error["causes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|cause| cause == "HTTP/1 exceeds its body bytes limit"),
        "{error}"
    );
    assert_staging_empty(directory.path());

    // HB13b: the artifact record draws once from the same
    // --max-application-output-bytes allowance the emitted events spent. An
    // allowance covering the messages but not the metadata fails at the
    // charge — before persistence — and leaves nothing behind.
    let reference_destination = directory.path().join("reference.bin");
    let reference = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--body-message",
        "2",
        "--write",
        path_text(&reference_destination),
    ]));
    std::fs::remove_file(&reference_destination).expect("reference artifact removes");
    let events_len: usize = ["messages", "issues"]
        .iter()
        .flat_map(|key| reference["result"][key].as_array().unwrap().iter())
        .map(|value| serde_json::to_vec(value).unwrap().len())
        .sum();
    for format in ["json", "ndjson", "text"] {
        let destination = directory.path().join(format!("body-{format}.bin"));
        // The charged size depends on the destination's own spelling.
        let mut metadata = reference["result"]["body_export"].clone();
        metadata["path"] = json!(path_text(&destination));
        let total = events_len + serde_json::to_vec(&metadata).unwrap().len();
        let under = (total - 1).to_string();
        let failure = run(&[
            "--output",
            format,
            "http",
            path,
            "--body-message",
            "2",
            "--write",
            path_text(&destination),
            "--max-application-output-bytes",
            &under,
        ]);
        assert_eq!(failure.status.code(), Some(6), "{format}");
        assert!(
            !destination.exists(),
            "{format}: the budget failure left an artifact"
        );
        if format == "ndjson" {
            // The emitted message prefix stays; the terminal record is the
            // error, never a complete.
            let records = parse_ndjson(&failure);
            assert_contiguous(&records);
            assert_eq!(events(&records), ["http_message", "http_message", "error"]);
            assert_eq!(records[2]["error"]["code"], "policy.denied");
        } else if format == "json" {
            assert_eq!(
                parse_json(&failure)["error"]["message"],
                "application output exceeds --max-application-output-bytes"
            );
        }
        // The exact allowance — events plus the artifact metadata — fits.
        let exact = total.to_string();
        run_success(&[
            "--output",
            format,
            "http",
            path,
            "--body-message",
            "2",
            "--write",
            path_text(&destination),
            "--max-application-output-bytes",
            &exact,
        ]);
        assert_eq!(std::fs::read(&destination).unwrap(), b"hello");
    }
}

#[cfg(packetcraftr_test_dev_full)]
#[test]
fn stdout_failure_before_and_after_persistence() {
    // HB14: an emit failure during inspection stops the run before the
    // commit boundary, so nothing publishes; once the artifact persists, an
    // unwritable report leaves it in place and reports the real failure.
    common::require_dev_full();
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );
    let file = capture.write();
    let path = path_text(file.path()).to_owned();
    let full = || {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full must be writable for the write-failure contract")
    };

    // Text emits each message row during inspection — the first write fails
    // long before the commit boundary.
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("before.bin");
    let failure = std::process::Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            "text",
            "http",
            &path,
            "--body-message",
            "2",
            "--write",
            path_text(&destination),
        ])
        .stdout(full())
        .output()
        .expect("CLI process must start");
    assert_eq!(failure.status.code(), Some(5), "{failure:?}");
    let stderr = String::from_utf8(failure.stderr).expect("stderr is UTF-8");
    assert!(stderr.starts_with("error[io."), "{stderr}");
    assert!(stderr.contains("stdout"), "{stderr}");
    assert_staging_empty(directory.path());

    // Aggregate JSON writes its whole report after the commit — the write
    // fails, the published artifact stays, and no false complete emits.
    let after = directory.path().join("after.bin");
    let failure = std::process::Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            "json",
            "http",
            &path,
            "--body-message",
            "2",
            "--write",
            path_text(&after),
        ])
        .stdout(full())
        .output()
        .expect("CLI process must start");
    assert_eq!(failure.status.code(), Some(5), "{failure:?}");
    let stderr = String::from_utf8(failure.stderr).expect("stderr is UTF-8");
    assert!(stderr.starts_with("error[io."), "{stderr}");
    assert!(stderr.contains("stdout"), "{stderr}");
    assert_eq!(std::fs::read(&after).unwrap(), b"hello");
}

#[test]
fn body_export_of_a_large_body_in_bounded_segments() {
    // HB15: a body delivered across many segments exports byte-exact without
    // retaining it — the staging file, not memory, holds the bytes. Bounded
    // sink spans and parser-buffer bounds are instrumented by the core
    // collector contracts; the CLI contract is the exact artifact.
    let mut body = Vec::with_capacity(256 * 1024);
    for segment in 0..64_u8 {
        body.extend(std::iter::repeat_n(segment, 4 * 1024));
    }
    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET /large HTTP/1.1\r\n\r\n");
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
    capture.server(&mut stream, at_ms(4_100), head.as_bytes());
    for (index, chunk) in body.chunks(4 * 1024).enumerate() {
        capture.server(&mut stream, at_ms(4_200 + index as u64 * 10), chunk);
    }
    let file = capture.write();
    let directory = tempfile::tempdir().expect("staging dir");
    let destination = directory.path().join("large.bin");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path_text(file.path()),
        "--body-message",
        "2",
        "--write",
        path_text(&destination),
    ]));
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    assert_eq!(
        document["result"]["body_export"]["bytes"],
        body.len() as u64
    );
    assert_eq!(
        document["result"]["body_export"]["sha256"],
        sha256_hex(&body)
    );
}

#[test]
fn body_export_reads_stdin_and_compressed_sources_identically() {
    // HB16: file, stdin, and compressed inputs produce the identical
    // artifact and digest.
    use packetcraftr_core::capture_file::compression;
    use std::io::Write as _;

    let (mut capture, mut stream) = opened_capture();
    capture.client(&mut stream, at_ms(4_000), b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        at_ms(4_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    );
    let bytes = capture.bytes();
    let digest = sha256_hex(b"hello");

    let directory = tempfile::tempdir().expect("staging dir");
    let stdin_destination = directory.path().join("stdin.bin");
    let stdin = run_with_stdin(
        &[
            "--output",
            "json",
            "http",
            "-",
            "--body-message",
            "2",
            "--write",
            path_text(&stdin_destination),
        ],
        &bytes,
    );
    assert!(stdin.status.success(), "{stdin:?}");
    assert_eq!(std::fs::read(&stdin_destination).unwrap(), b"hello");
    assert_eq!(
        parse_json(&stdin)["result"]["body_export"]["sha256"],
        digest
    );

    for format in [compression::Format::Gzip, compression::Format::Zstd] {
        let mut encoder =
            compression::Output::new(Vec::new(), format).expect("compressor must open");
        encoder
            .write_all(&bytes)
            .expect("compression must accept bytes");
        let compressed = encoder.finish().expect("compressed stream must finish");
        let mut file = tempfile::NamedTempFile::new().expect("temporary capture");
        file.write_all(&compressed)
            .expect("compressed capture writes");
        file.flush().expect("compressed capture flushes");
        let directory = tempfile::tempdir().expect("staging dir");
        let destination = directory.path().join("compressed.bin");
        let document = parse_json(&run_success(&[
            "--output",
            "json",
            "http",
            path_text(file.path()),
            "--body-message",
            "2",
            "--write",
            path_text(&destination),
        ]));
        assert_eq!(std::fs::read(&destination).unwrap(), b"hello");
        assert_eq!(document["result"]["body_export"]["sha256"], digest);
    }
}

/// Regenerates the published `output-http-transaction*` documents from the
/// real CLI serializer. Run explicitly after changing the v7 transaction
/// contract:
///
/// `cargo test -p packetcraftr-cli --test http_contracts refresh_published -- --ignored`
#[test]
#[ignore = "refreshes examples/documents; run explicitly to regenerate"]
fn refresh_published_transaction_examples() {
    let documents =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    // One conversation covering a paired row with an informational response
    // and a signed (negative) wait; a sibling conversation's orphan row; and
    // a third whose request retires unanswered at end of input.
    let mut capture = Capture::new();
    let mut first = Stream::new(40_000);
    let mut second = Stream::new(40_001);
    let mut third = Stream::new(40_002);
    capture.open(&mut first, at_ms(0));
    capture.client(
        &mut first,
        at_ms(5_000),
        b"GET /resource HTTP/1.1\r\nHost: example.test\r\n\r\n",
    );
    capture.server(&mut first, at_ms(5_200), b"HTTP/1.1 100 Continue\r\n\r\n");
    // The capture clock regresses across the response's first segment, so
    // the wait serializes negative while the span stays positive.
    capture.server(&mut first, at_ms(4_800), b"HTTP/1.1 200");
    capture.server(
        &mut first,
        at_ms(6_000),
        b" OK\r\nContent-Length: 0\r\n\r\n",
    );
    capture.open(&mut second, at_ms(7_000));
    capture.server(
        &mut second,
        at_ms(7_100),
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    capture.open(&mut third, at_ms(8_000));
    capture.client(
        &mut third,
        at_ms(8_500),
        b"GET /unanswered HTTP/1.1\r\n\r\n",
    );
    let file = capture.write();
    let path = path_text(file.path());
    let aggregate = run_success(&["--output", "json", "http", path, "--transactions"]);
    std::fs::write(
        documents.join("output-http-transactions-success.json"),
        &aggregate.stdout,
    )
    .expect("aggregate example must write");
    // Event and terminal documents keep the emitted key order; the lines are
    // only re-indented, so the files read exactly as the serializer wrote them.
    let output = run_success(&["--output", "ndjson", "http", path, "--transactions"]);
    let stdout = String::from_utf8(output.stdout).expect("NDJSON output is UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    let records: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("emitted record parses"))
        .collect();
    let write_record = |name: &str, index: usize| {
        std::fs::write(
            documents.join(name),
            format!("{}\n", pretty_preserve_order(lines[index])),
        )
        .unwrap_or_else(|error| panic!("{name} must write: {error}"));
    };
    let find = |event: &str, outcome: Option<&str>| {
        records
            .iter()
            .position(|record| {
                record["event"] == event
                    && outcome.is_none_or(|outcome| record["result"]["outcome"] == outcome)
            })
            .unwrap_or_else(|| panic!("a {event} record must publish"))
    };
    write_record(
        "output-http-transaction-event.json",
        find("http_transaction", Some("paired")),
    );
    write_record(
        "output-http-transaction-unanswered-event.json",
        find("http_transaction", Some("unanswered")),
    );
    write_record(
        "output-http-transactions-complete.json",
        find("complete", None),
    );
}

/// Re-indents compact JSON with two spaces without reordering keys, matching
/// the style of the CLI's own pretty output.
fn pretty_preserve_order(compact: &str) -> String {
    let mut out = String::with_capacity(compact.len() * 2);
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    let bytes = compact.as_bytes();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        index += 1;
        if in_string {
            out.push(char::from(byte));
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                out.push('"');
            }
            b'{' | b'[' => {
                let close = if byte == b'{' { b'}' } else { b']' };
                out.push(char::from(byte));
                if bytes.get(index) == Some(&close) {
                    out.push(char::from(close));
                    index += 1;
                } else {
                    depth += 1;
                    out.push('\n');
                    out.push_str(&"  ".repeat(depth));
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
                out.push(char::from(byte));
            }
            b',' => {
                out.push(',');
                out.push('\n');
                out.push_str(&"  ".repeat(depth));
            }
            b':' => out.push_str(": "),
            b' ' | b'\t' | b'\r' | b'\n' => {}
            _ => out.push(char::from(byte)),
        }
    }
    out
}
