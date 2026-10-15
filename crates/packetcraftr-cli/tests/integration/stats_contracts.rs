// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use packetcraftr_core::{build::Builder, expression, protocol::builtin};
use serde_json::{Value, json};

use crate::{
    capture_support::{Record, write_records},
    common,
};

fn fixture() -> tempfile::NamedTempFile {
    let registry = builtin::registry();
    let mut records = Vec::new();
    for (transport, source, destination, sport, dport, payload, second, count) in [
        ("udp", 1, 2, 1111, 2222, 1, 1, 3),
        ("udp", 2, 1, 2222, 1111, 1, 1, 1),
        ("tcp", 3, 4, 3333, 4444, 1024, 2, 1),
        ("udp", 5, 6, 5555, 6666, 256, 3, 1),
        ("udp", 7, 8, 7777, 8888, 256, 4, 1),
    ] {
        let source = format!(
            "ipv4(src=192.0.2.{source},dst=192.0.2.{destination})/{transport}(sport={sport},dport={dport})/raw(hex=\"{}\")",
            "51".repeat(payload)
        );
        let packet = expression::parse(&source, &registry, Default::default()).unwrap();
        let built = Builder::new(registry.clone())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        for _ in 0..count {
            records.push(Record::new((second, 123_456), built.bytes.to_vec()));
        }
    }
    write_records(&records)
}

fn document(path: &Path, table: &str, flags: &[&str]) -> Value {
    let mut args = vec![
        "--output",
        "json",
        "analyze",
        "stats",
        common::path_text(path),
        "--table",
        table,
    ];
    args.extend_from_slice(flags);
    common::parse_json(&common::run_success(&args))
}

fn capture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures")
        .join(name)
}

#[test]
fn overview_totals_survive_independent_limits_and_preserve_scoped_rows() {
    check_overview(&capture("scoped-vxlan.pcap"));
    let file = fixture();
    check_overview(file.path());
}

fn check_overview(path: &Path) {
    let overview = document(path, "overview", &["--top", "100", "--sort", "bytes"]);
    assert_eq!(overview["schema"], "packetcraftr.output/v18");
    for (table, count) in [
        ("protocols", "protocol_count"),
        ("endpoints", "endpoint_count"),
        ("conversations", "conversation_count"),
    ] {
        let individual = document(path, table, &["--sort", "bytes"]);
        assert_eq!(overview["result"][table], individual["result"][table]);
        assert_eq!(
            overview["result"][count],
            individual["result"][table].as_array().unwrap().len()
        );
        for key in [
            "frames_read",
            "frames_matched",
            "bytes_matched",
            "interfaces",
            "duration",
            "first_timestamp",
            "last_timestamp",
            "average_packet_size",
            "packets_per_second",
            "bytes_per_second",
        ] {
            assert_eq!(overview["result"][key], individual["result"][key], "{key}");
        }
    }
    let limited = document(path, "overview", &["--top", "1"]);
    let totals_only = document(path, "overview", &["--top", "0"]);
    for (table, count) in [
        ("protocols", "protocol_count"),
        ("endpoints", "endpoint_count"),
        ("conversations", "conversation_count"),
    ] {
        assert_eq!(limited["result"][table].as_array().unwrap().len(), 1);
        assert_eq!(totals_only["result"][table], json!([]));
        assert_eq!(limited["result"][count], overview["result"][count]);
        assert_eq!(totals_only["result"][count], overview["result"][count]);
    }
    assert_eq!(totals_only["diagnostics"].as_array().unwrap().len(), 3);
}

#[test]
fn overview_requires_counts_in_v17_and_does_not_change_v16() {
    let file = fixture();
    let original = document(file.path(), "overview", &[]);
    for field in ["protocol_count", "endpoint_count", "conversation_count"] {
        let mut invalid = original.clone();
        invalid["result"].as_object_mut().unwrap().remove(field);
        assert!(!common::schema_validator().is_valid(&invalid), "{field}");
    }
    let mut old_family = original;
    old_family["schema"] = "packetcraftr.output/v16".into();
    assert!(!common::frozen_v16_schema_validator().is_valid(&old_family));
}

#[test]
fn overview_default_limit_and_resource_sources_are_effective() {
    let file = fixture();
    for (flags, top, source) in [
        (vec![], 5, "default"),
        (vec!["--resource-preset", "ci-v1"], 5, "default"),
        (
            vec!["--resource-preset", "workstation-v1", "--top", "0"],
            0,
            "override",
        ),
    ] {
        let mut args = vec![
            "--output",
            "json",
            "--resource-diagnostics",
            "stats",
            common::path_text(file.path()),
            "--table",
            "overview",
        ];
        args.extend(flags);
        let doc = common::parse_json(&common::run_success(&args));
        let setting = doc["resources"]["settings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["name"] == "--top")
            .unwrap();
        assert_eq!(setting["value"], top);
        assert_eq!(setting["source"], source);
        assert_eq!(
            doc["result"]["endpoints"].as_array().unwrap().len(),
            top as usize
        );
    }
}

#[test]
fn sorting_uses_directional_totals_secondary_metrics_and_natural_ties_before_top() {
    let file = fixture();
    for (sort, first_address, first_port, first_offset, first_stream) in [
        ("frames", "192.0.2.1", 1111, 0, ("udp", 0)),
        ("bytes", "192.0.2.3", 3333, 1, ("tcp", 0)),
    ] {
        let args = ["--sort", sort, "--top", "1"];
        let row = &document(file.path(), "endpoints", &args)["result"]["endpoints"][0];
        assert_eq!(row["address"], first_address);
        let row = &document(file.path(), "ports", &args)["result"]["ports"][0];
        assert_eq!(row["port"], first_port);
        let row = &document(file.path(), "io", &args)["result"]["io"]["buckets"][0];
        assert_eq!(row["offset"]["secs"], first_offset);
        let row = &document(file.path(), "conversations", &args)["result"]["conversations"][0];
        assert_eq!(row["transport"], first_stream.0);
        assert_eq!(row["stream"], first_stream.1);
        let all = document(file.path(), "conversations", &["--sort", sort]);
        let rows = all["result"]["conversations"].as_array().unwrap();
        assert_eq!(rows[if sort == "frames" { 2 } else { 1 }]["stream"], 1);
        assert_eq!(rows[3]["stream"], if sort == "frames" { 2 } else { 0 });
    }
    let frames = document(file.path(), "protocols", &["--sort", "frames"]);
    let bytes = document(file.path(), "protocols", &["--sort", "bytes"]);
    let position = |doc: &Value, name: &str| {
        doc["result"]["protocols"]
            .as_array()
            .unwrap()
            .iter()
            .position(|r| r["protocol"] == name)
            .unwrap()
    };
    assert!(position(&frames, "udp") < position(&frames, "tcp"));
    assert!(position(&bytes, "tcp") < position(&bytes, "udp"));
    let default = document(file.path(), "conversations", &[]);
    assert_eq!(default["result"]["conversations"][0]["transport"], "tcp");
    let capped = document(file.path(), "conversations", &["--top", "1"]);
    assert_eq!(capped["result"]["conversations"][0]["transport"], "udp");
    assert_eq!(
        document(file.path(), "io", &[])["result"]["io"]["buckets"][0]["offset"]["secs"],
        0
    );
}

// Decode standard quoted CSV, including embedded line endings, without changing cell contents.
fn csv(bytes: &[u8]) -> Vec<Vec<String>> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(text.ends_with("\r\n"));
    let mut chars = text.chars().peekable();
    let (mut rows, mut row, mut cell, mut quoted) = (Vec::new(), Vec::new(), String::new(), false);
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                cell.push('"');
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut cell)),
            '\r' if !quoted => {
                assert_eq!(chars.next(), Some('\n'));
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            _ => cell.push(ch),
        }
    }
    assert!(!quoted);
    rows
}

fn time(value: &Value) -> String {
    if value.is_null() {
        return String::new();
    }
    if let Some(seconds) = value["unix_seconds"].as_i64() {
        packetcraftr_cli::output::frame::Timestamp {
            unix_seconds: seconds,
            nanoseconds: value["nanoseconds"].as_u64().unwrap() as u32,
        }
        .to_string()
    } else {
        format!(
            "{}.{:09}",
            value["secs"].as_u64().unwrap(),
            value["nanos"].as_u64().unwrap()
        )
    }
}

#[test]
fn csv_fields_order_precision_and_scope_match_json_without_stdout_diagnostics() {
    let file = fixture();
    for path in [
        file.path(),
        capture("scoped-vxlan.pcap").as_path(),
        capture("clock-regression.pcap").as_path(),
    ] {
        for table in ["conversations", "endpoints", "protocols", "ports", "io"] {
            let output = common::run_success(&[
                "--output",
                "csv",
                "stats",
                common::path_text(path),
                "--table",
                table,
                "--sort",
                "bytes",
                "--top",
                "1",
            ]);
            let rows = csv(&output.stdout);
            let headers = &rows[0];
            let document = document(path, table, &["--sort", "bytes", "--top", "1"]);
            let result = &document["result"];
            let entries = if table == "io" {
                &result["io"]["buckets"]
            } else {
                &result[table]
            }
            .as_array()
            .unwrap();
            assert_eq!(rows.len(), entries.len() + 1);
            for (actual, expected) in rows[1..].iter().zip(entries) {
                assert_eq!(actual.len(), headers.len());
                for (header, cell) in headers.iter().zip(actual) {
                    match header.as_str() {
                        "scope_encapsulation" => assert_eq!(
                            serde_json::from_str::<Value>(cell).unwrap(),
                            expected["scope"]["encapsulation"]
                        ),
                        "scope_id" => assert_eq!(*cell, expected["scope"]["id"].to_string()),
                        "scope_interface" => assert_eq!(
                            *cell,
                            expected["scope"]["interface"]
                                .as_u64()
                                .map(|v| v.to_string())
                                .unwrap_or_default()
                        ),
                        "first_timestamp" | "last_timestamp" | "duration" | "offset" => {
                            assert_eq!(*cell, time(&expected[header]));
                        }
                        "origin" | "interval" => assert_eq!(*cell, time(&result["io"][header])),
                        "underflow_frames" => assert_eq!(*cell, result["io"][header].to_string()),
                        _ => assert_eq!(
                            *cell,
                            expected[header]
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| expected[header].to_string())
                        ),
                    }
                }
            }
            if !document["diagnostics"].as_array().unwrap().is_empty() {
                assert!(String::from_utf8_lossy(&output.stderr).contains("omitted"));
            }
            let expected_header = match table {
                "conversations" => {
                    "transport,stream,scope_id,scope_interface,scope_encapsulation,address_a,port_a,address_b,port_b,frames_a_to_b,bytes_a_to_b,frames_b_to_a,bytes_b_to_a,first_timestamp,last_timestamp,duration"
                }
                "endpoints" => "address,tx_frames,tx_bytes,rx_frames,rx_bytes",
                "protocols" => "protocol,frames,bytes",
                "ports" => "transport,port,frames,bytes",
                _ => "origin,underflow_frames,interval,offset,frames,bytes",
            };
            assert_eq!(headers.join(","), expected_header);
        }
    }
}

#[test]
fn empty_filters_zero_span_and_header_only_csv() {
    let empty = write_records(&[]);
    let file = fixture();
    for (path, flags) in [
        (empty.path(), vec![]),
        (file.path(), vec!["--filter", "udp.srcport == 9999"]),
    ] {
        let doc = document(path, "overview", &flags);
        assert_eq!(doc["result"]["frames_matched"], 0);
        assert!(doc["result"].get("duration").is_none());
        assert!(doc["result"].get("average_packet_size").is_none());
        for table in ["conversations", "endpoints", "protocols", "ports", "io"] {
            let mut args = vec![
                "--output",
                "csv",
                "stats",
                common::path_text(path),
                "--table",
                table,
            ];
            args.extend_from_slice(&flags);
            assert_eq!(csv(&common::run_success(&args).stdout).len(), 1);
        }
    }
    let doc = document(
        file.path(),
        "overview",
        &["--filter", "udp.srcport == 1111"],
    );
    assert_eq!(doc["result"]["frames_matched"], 3);
    assert_eq!(doc["result"]["duration"], json!({"secs": 0, "nanos": 0}));
    assert!(doc["result"].get("packets_per_second").is_none());
    assert!(doc["result"].get("bytes_per_second").is_none());
    let text = common::run_success(&[
        "stats",
        common::path_text(file.path()),
        "--table",
        "overview",
        "--top",
        "0",
    ]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("7 of 7 frame(s)"));
    assert!(text.contains("8 endpoint(s), 4 conversation(s)"));
    assert!(text.contains("timestamps 1.123456000 to 4.123456000; 1 interface(s)"));
}

#[test]
fn csv_preserves_pre_epoch_nanoseconds_and_subsecond_durations() {
    use packetcraftr_core::capture_file::{Interface, Reader, TimestampResolution, Writer};
    use packetcraftr_core::frame::{Frame, LinkType};
    use std::time::{Duration, UNIX_EPOCH};

    let source = fixture();
    let first = Reader::new(std::fs::File::open(source.path()).unwrap())
        .unwrap()
        .next_frame()
        .unwrap()
        .unwrap();
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer
        .add_interface_description(Interface {
            link_type: LinkType::IPV4,
            snap_len: 65_535,
            timestamp_resolution: TimestampResolution::Decimal(9),
            timestamp_offset: -1,
        })
        .unwrap();
    for timestamp in [
        UNIX_EPOCH - Duration::from_nanos(123_456_789),
        UNIX_EPOCH + Duration::from_nanos(1),
    ] {
        writer
            .write_frame(&Frame::new(timestamp, LinkType::IPV4, first.bytes().clone()).unwrap())
            .unwrap();
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), writer.into_inner()).unwrap();
    let rows =
        csv(
            &common::run_success(&["--output", "csv", "stats", common::path_text(file.path())])
                .stdout,
        );
    assert_eq!(
        &rows[1][13..],
        ["-0.123456789", "0.000000001", "0.123456790"]
    );
    let rows = csv(&common::run_success(&[
        "--output",
        "csv",
        "stats",
        common::path_text(file.path()),
        "--table",
        "io",
    ])
    .stdout);
    assert_eq!(&rows[1][..3], ["-0.123456789", "0", "1.000000000"]);
}

#[test]
fn invalid_combinations_fail_before_opening_input() {
    for flags in [
        vec!["--output", "csv", "stats", "--table", "overview"],
        vec!["--output", "csv", "stats", "--table", "fragments"],
        vec!["stats", "--table", "fragments", "--sort", "frames"],
        vec!["--output", "csv", "read"],
    ] {
        let mut args = flags;
        args.push("/missing/stats-capture.pcap");
        let output = common::run(&args);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("open capture"));
    }
}

#[test]
fn stdin_compression_and_resource_failures_preserve_csv_publication_contract() {
    let file = fixture();
    let bytes = std::fs::read(file.path()).unwrap();
    crate::capture_support::assert_file_stdin_parity(
        &bytes,
        "stats",
        &["--table", "overview", "--sort", "bytes"],
        "json",
        0,
    );
    crate::capture_support::assert_file_stdin_parity(
        &bytes,
        "stats",
        &["--table", "conversations", "--sort", "bytes"],
        "csv",
        0,
    );
    let gzip = file.path().with_extension("pcap.gz");
    // Use the CLI's compressor so the compressed input follows the public path too.
    let out = common::run_success(&[
        "export",
        common::path_text(file.path()),
        "--write",
        common::path_text(&gzip),
        "--compression",
        "gzip",
        "--filter",
        "ip",
    ]);
    assert!(out.status.success());
    for (format, table) in [("json", "overview"), ("csv", "conversations")] {
        let args = |path: &Path| {
            common::run_success(&[
                "--output",
                format,
                "stats",
                common::path_text(path),
                "--table",
                table,
                "--sort",
                "bytes",
            ])
        };
        assert_eq!(args(file.path()).stdout, args(&gzip).stdout);
    }
    std::fs::remove_file(gzip).unwrap();
    for flags in [["--max-bytes", "1"], ["--max-flows", "1"]] {
        let output = common::run(&[
            "--output",
            "csv",
            "stats",
            common::path_text(file.path()),
            flags[0],
            flags[1],
        ]);
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "analysis must complete before a header is written"
        );
    }
}

#[cfg(packetcraftr_test_dev_full)]
#[test]
fn csv_write_failure_is_nonzero_and_reported_on_stderr() {
    common::require_dev_full();
    let file = fixture();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            "csv",
            "stats",
            common::path_text(file.path()),
            "--table",
            "endpoints",
        ])
        .stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&output.stderr).contains("io.stdout"));
}

#[test]
fn rtt_tables_report_handshake_and_data_evidence() {
    let report = document(&capture("tls-handshake.pcapng"), "rtt", &[]);
    assert_eq!(report["result"]["table"], "rtt");
    let rows = report["result"]["rtt"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["transport"], "tcp");
    assert_eq!(row["stream"], 0);
    assert_eq!(row["address_a"], "192.0.2.1");
    assert_eq!(row["port_a"], 54321);
    assert_eq!(row["address_b"], "198.51.100.2");
    assert_eq!(row["port_b"], 443);
    // The capture stamps the handshake's SYN eight milliseconds before its
    // SYN-ACK, and the two data exchanges measure 19 and 24 milliseconds.
    assert_eq!(row["handshake_rtt_ns"], 8_000_000);
    assert_eq!(row["samples"], 2);
    assert_eq!(row["min_rtt_ns"], 19_000_000);
    assert_eq!(row["mean_rtt_ns"], 21_500_000);
    assert_eq!(row["max_rtt_ns"], 24_000_000);

    // CSV exports the same rows under the documented header.
    let csv = common::run_success(&[
        "--output",
        "csv",
        "analyze",
        "stats",
        common::path_text(&capture("tls-handshake.pcapng")),
        "--table",
        "rtt",
    ]);
    let text = String::from_utf8_lossy(&csv.stdout);
    assert!(
        text.starts_with(
            "transport,stream,scope_id,scope_interface,scope_encapsulation,address_a,port_a,\
             address_b,port_b,handshake_rtt_ns,samples,min_rtt_ns,mean_rtt_ns,max_rtt_ns\r\n"
        ),
        "csv header: {text}"
    );
    assert!(
        text.contains("tcp,0,0,0,[],192.0.2.1,54321,198.51.100.2,443,"),
        "csv row: {text}"
    );
    assert!(
        text.contains("8000000,2,19000000,21500000,24000000"),
        "{text}"
    );

    // Compact text keeps the stream order and names each measured value.
    let rendered = common::run_success(&[
        "analyze",
        "stats",
        common::path_text(&capture("tls-handshake.pcapng")),
        "--table",
        "rtt",
    ]);
    let text = String::from_utf8_lossy(&rendered.stdout);
    assert!(
        text.contains("handshake_rtt 8.000ms samples 2 min 19.000ms mean 21.500ms max 24.000ms"),
        "{text}"
    );
}

#[test]
fn rtt_tables_reject_sorting_and_cap_rows_with_diagnostics() {
    let sorted = common::run(&[
        "analyze",
        "stats",
        common::path_text(&capture("tls-handshake.pcapng")),
        "--table",
        "rtt",
        "--sort",
        "frames",
    ]);
    assert_eq!(sorted.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&sorted.stderr).contains("--sort is not supported"),
        "{:?}",
        String::from_utf8_lossy(&sorted.stderr)
    );

    let capped = document(&capture("tls-handshake.pcapng"), "rtt", &["--top", "0"]);
    assert_eq!(capped["result"]["rtt"], json!([]));
    assert_eq!(capped["diagnostics"].as_array().unwrap().len(), 1);
    assert_eq!(capped["diagnostics"][0]["code"], "stats.rtt_omitted");

    // A capture without TCP conversations reports an empty table, not an error.
    let udp_only = document(&capture("dns-response.pcap"), "rtt", &[]);
    assert_eq!(udp_only["result"]["rtt"], json!([]));
}
