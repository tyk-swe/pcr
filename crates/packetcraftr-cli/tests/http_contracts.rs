// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};

fn encoded_entity_capture(path: &std::path::Path, encoding: &str, encoded: &[u8]) {
    use packetcraftr_core::{
        build::Builder,
        capture_file::Writer,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, network::Ipv4, transport::Tcp},
    };
    use std::time::{Duration, UNIX_EPOCH};
    let mut writer = Writer::pcap(Vec::new(), LinkType::IPV4).unwrap();
    let mut payload = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: {encoding}\r\n\r\n",
        encoded.len()
    )
    .into_bytes();
    payload.extend_from_slice(encoded);
    for (index, (sequence, flags, bytes)) in [
        (10, Tcp::SYN | Tcp::ACK, Vec::new()),
        (11, Tcp::ACK, payload),
    ]
    .into_iter()
    .enumerate()
    {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: "198.51.100.2".parse().unwrap(),
            destination: "192.0.2.1".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Tcp {
            source_port: 80,
            destination_port: 40000,
            sequence,
            flags,
            ..Default::default()
        });
        packet.push(Raw::new(bytes));
        let built = Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(index as u64),
                    LinkType::IPV4,
                    built.bytes,
                )
                .unwrap(),
            )
            .unwrap();
    }
    std::fs::write(path, writer.into_inner()).unwrap();
}

#[test]
fn empty_decoded_entity_fits_an_exact_encoded_only_export_budget() {
    let root = tempfile::tempdir().unwrap();
    for (encoding, hex) in [
        ("gzip", "1f8b08000000000002ff03000000000000000000"),
        ("deflate", "789c030000000001"),
    ] {
        let encoded: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect();
        let capture = root.path().join(format!("{encoding}.pcap"));
        encoded_entity_capture(&capture, encoding, &encoded);
        let write = root.path().join(encoding);
        let maximum = encoded.len().to_string();
        let report = parse_json(&run_success(&[
            "--output",
            "json",
            "http",
            capture.to_str().unwrap(),
            "--write",
            write.to_str().unwrap(),
            "--decode-content",
            "--max-http-export-bytes",
            &maximum,
        ]));
        let entity = &report["result"]["messages"][0]["entity"];
        assert_eq!(entity["decoded_bytes"], 0);
        assert!(
            std::fs::read(entity["decoded_path"].as_str().unwrap())
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn content_export_keeps_encoded_and_decoded_files_and_cleans_failed_publication() {
    let root = tempfile::tempdir().unwrap();
    for (encoding, hex) in [
        ("gzip", "1f8b08000000000002ffcb48cdc9c9070086a6103605000000"),
        ("deflate", "789ccb48cdc9c90700062c0215"),
    ] {
        let encoded: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect();
        let capture = root.path().join(format!("{encoding}.pcap"));
        encoded_entity_capture(&capture, encoding, &encoded);
        let write = root.path().join(encoding);
        let report = parse_json(&run_success(&[
            "--output",
            "json",
            "http",
            capture.to_str().unwrap(),
            "--write",
            write.to_str().unwrap(),
            "--decode-content",
            "--max-http-body-bytes",
            if encoding == "deflate" {
                "268435456"
            } else {
                "16777216"
            },
        ]));
        let entity = &report["result"]["messages"][0]["entity"];
        assert_eq!(
            std::fs::read(entity["path"].as_str().unwrap()).unwrap(),
            encoded
        );
        assert_eq!(
            std::fs::read(entity["decoded_path"].as_str().unwrap()).unwrap(),
            b"hello"
        );
        assert_eq!(entity["decoded_bytes"], 5);
        let failed = root.path().join(format!("{encoding}-failed"));
        let maximum = (encoded.len() + 4).to_string();
        assert!(
            !run(&[
                "http",
                capture.to_str().unwrap(),
                "--write",
                failed.to_str().unwrap(),
                "--decode-content",
                "--max-http-export-bytes",
                &maximum
            ])
            .status
            .success()
        );
        assert!(!failed.exists());
        let broken = root.path().join(format!("{encoding}-broken.pcap"));
        encoded_entity_capture(&broken, encoding, &encoded[..encoded.len() / 2]);
        assert!(
            !run(&[
                "http",
                broken.to_str().unwrap(),
                "--write",
                failed.to_str().unwrap(),
                "--decode-content"
            ])
            .status
            .success()
        );
        assert!(!failed.exists());
    }
}

#[test]
fn entity_export_writes_dechunked_bytes_and_removes_incomplete_objects() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let root = tempfile::tempdir().unwrap();
    let write = root.path().join("entities");
    let args = [
        "--output",
        "json",
        "http",
        path.to_str().unwrap(),
        "--write",
        write.to_str().unwrap(),
    ];
    let report = parse_json(&run_success(&args));
    let entity = &report["result"]["messages"][1]["entity"];
    assert_eq!(entity["bytes"], 5);
    assert_eq!(
        std::fs::read(entity["path"].as_str().unwrap()).unwrap(),
        b"hello"
    );
    assert!(!run(&args).status.success());
    let partial = root.path().join("partial");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path.to_str().unwrap(),
        "--write",
        partial.to_str().unwrap(),
        "--max-http-body-bytes",
        "4",
    ]));
    assert_eq!(report["result"]["messages"][1]["status"], "limit");
    assert!(report["result"]["messages"][1].get("entity").is_none());
    assert_eq!(std::fs::read_dir(partial).unwrap().count(), 0);
    let exhausted = root.path().join("exhausted");
    assert!(
        !run(&[
            "http",
            path.to_str().unwrap(),
            "--write",
            exhausted.to_str().unwrap(),
            "--max-http-export-bytes",
            "1"
        ])
        .status
        .success()
    );
    assert!(!exhausted.exists());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
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
fn http_rejects_zero_ports_and_out_of_range_body_limits_as_usage_errors() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    for (flag, value) in [
        ("--http-port", "0"),
        ("--max-http-body-bytes", "0"),
        ("--max-http-body-bytes", "268435457"),
    ] {
        let output = run(&["--output", "json", "http", path, flag, value]);
        assert_eq!(output.status.code(), Some(2), "{flag} {value}: {output:?}");
        let error = parse_json(&output)["error"].clone();
        assert_eq!(error["kind"], "cli", "{flag} {value}");
        assert!(
            error["message"].as_str().unwrap().contains(flag),
            "{flag} {value}: {error}"
        );
    }
    let accepted = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--max-http-body-bytes",
        "268435456",
        "--http-port",
        "65535",
    ]));
    assert_eq!(accepted["result"]["messages"].as_array().unwrap().len(), 2);
}

#[test]
fn application_output_budget_counts_only_compact_event_payloads() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let expected_text = concat!(
        "HTTP tcp:0 message=1 status=complete GET /example body_bytes=0 request=none frames=4,5\n",
        "  Host: example.test\n",
        "  X-Test: one\n",
        "  X-Test: two\n",
        "HTTP tcp:0 message=2 status=complete 200 OK body_bytes=5 request=1 frames=6,7\n",
        "  Transfer-Encoding: chunked\n",
        "2 HTTP/1 messages, 2 complete, 0 incomplete, 0 malformed; 0 requests without a captured final response\n",
    );
    common::application_output::assert_exact_budget(
        "http",
        &path,
        &[
            ("http_message", "messages"),
            ("http_stream_issue", "issues"),
        ],
        expected_text,
        "analysis consumer failed at frame 7",
        &["application output exceeds --max-application-output-bytes"],
    );
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

#[test]
fn zero_application_message_limit_is_a_usage_error() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--max-application-messages",
        "0",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let error = &parse_json(&output)["error"];
    assert_eq!(error["code"], "cli.analysis_limit");
    assert_eq!(error["kind"], "cli");
    assert!(
        error["message"].as_str().unwrap().contains("max_messages"),
        "{error}"
    );
}

#[test]
fn content_expansion_limit_cleans_all_staged_files() {
    let root = tempfile::tempdir().unwrap();
    for (encoding, encoded) in [
        (
            "gzip",
            vec![
                31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 75, 76, 28, 5, 35, 13, 0, 0, 17, 65, 146, 5,
                244, 1, 0, 0,
            ],
        ),
        (
            "deflate",
            vec![120, 156, 75, 76, 28, 5, 35, 13, 0, 0, 110, 205, 189, 117],
        ),
    ] {
        let input = root.path().join(format!("{encoding}.pcap"));
        encoded_entity_capture(&input, encoding, &encoded);
        let failed = root.path().join(format!("{encoding}-objects"));
        let output = run(&[
            "--output",
            "json",
            "http",
            input.to_str().unwrap(),
            "--write",
            failed.to_str().unwrap(),
            "--decode-content",
            "--max-http-body-bytes",
            "100",
        ]);
        assert!(!output.status.success());
        assert_eq!(parse_json(&output)["error"]["kind"], "policy");
        assert!(!failed.exists());
    }
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
}
