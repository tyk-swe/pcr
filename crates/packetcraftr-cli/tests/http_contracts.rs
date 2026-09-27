// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
#[path = "common/http_capture.rs"]
mod http_capture;
#[path = "common/process.rs"]
mod process_support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success};
use http_capture::{Capture, Stream};
use process_support::run_with_stdin;
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
