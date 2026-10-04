// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::path::PathBuf;

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{TCP_CLIENT, UDP_CLIENT, UDP_SERVER, write_pcap_hex};
use common::{assert_contiguous, parse_json, parse_ndjson, path_text, run};
use process_support::decode_hex;

/// `UDP_CLIENT` with its last payload byte flipped, so the UDP checksum fails.
fn damaged_udp_client() -> Vec<u8> {
    let mut frame = decode_hex(UDP_CLIENT);
    *frame.last_mut().expect("UDP payload") ^= 1;
    frame
}
const TCP_SERVER: &str =
    "450000280000000040068e99c6336402c0000201005030390000000a000000045012100083040000";
const TCP_DATA: &str =
    "4500002b0000000040068e96c0000201c633640230390050000000040000000b50181000be970000616263";

fn write_capture() -> tempfile::NamedTempFile {
    write_pcap_hex(&[UDP_CLIENT, UDP_SERVER, TCP_CLIENT, TCP_SERVER, TCP_DATA])
}

#[test]
fn follow_reject_absent_tcp_udp_strms_format() {
    for capture in [write_capture(), write_pcap_hex(&[])] {
        let path = path_text(capture.path());
        for selector in ["tcp:999", "udp:999"] {
            let expected = format!("--stream {selector} is not present");
            for format in ["text", "hex", "raw", "json", "ndjson"] {
                let output = run(&[
                    "--output",
                    format,
                    "follow",
                    path,
                    "--stream",
                    selector,
                    "--direction",
                    "client",
                ]);
                assert_eq!(output.status.code(), Some(2), "{format}: {output:?}");
                if matches!(format, "text" | "hex" | "raw") {
                    assert!(output.stdout.is_empty(), "no success payload: {output:?}");
                    assert!(String::from_utf8_lossy(&output.stderr).contains(&expected));
                    continue;
                }
                let error = if format == "ndjson" {
                    let records = parse_ndjson(&output);
                    assert_contiguous(&records);
                    assert_eq!(records.len(), 1, "only one terminal error");
                    records[0].clone()
                } else {
                    parse_json(&output)
                };
                assert_eq!(error["status"], "error");
                assert_eq!(error["error"]["code"], "cli.error");
                assert_eq!(error["error"]["message"], expected);
                assert!(error.get("result").is_none());
            }
        }
    }
}

#[test]
fn format_limit_fails_before_offline_work() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("does-not-exist.pcap");
    let missing = path_text(&missing);
    let unsupported = run(&["--output", "raw", "stats", missing]);
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unsupported.stderr).contains("does not support raw"));

    for arguments in [
        vec!["stats", missing, "--max-ip-datagrams", "0"],
        vec!["expert", missing, "--max-ip-fragments-per-datagram", "0"],
        vec![
            "follow",
            missing,
            "--stream",
            "tcp:0",
            "--max-ip-bytes-per-datagram",
            "0",
        ],
        vec!["tls", missing, "--max-ip-reassembly-bytes", "0"],
        vec!["stats", missing, "--max-ip-outcomes", "0"],
        vec!["expert", missing, "--ip-idle-expiry-ms", "0"],
        vec!["stats", missing, "--max-tcp-bytes-per-flow", "0"],
        vec!["expert", missing, "--max-tcp-reassembly-bytes", "0"],
        vec![
            "follow",
            missing,
            "--stream",
            "tcp:0",
            "--max-tcp-segments-per-flow",
            "0",
        ],
        vec!["tls", missing, "--tcp-idle-expiry-ms", "0"],
        // The per-flow window doubles as the reordering window, so the
        // serial half-space is refused before the capture is opened.
        vec!["stats", missing, "--max-tcp-bytes-per-flow", "2147483648"],
        vec!["stats", missing, "--ip-overlap", "invalid"],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("open "),
            "{arguments:?} must fail before opening the capture"
        );
    }
    for policy in ["reject", "first", "last"] {
        let output = run(&["stats", missing, "--ip-overlap", policy]);
        assert_eq!(output.status.code(), Some(5), "{policy}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("open "),
            "valid overlap policy {policy} must reach capture opening"
        );
    }

    let capture = write_capture();
    let path = path_text(capture.path());
    for arguments in [
        vec!["stats", path, "--interval-ms", "0"],
        vec!["stats", path, "--max-frames", "0"],
        vec!["expert", path, "--max-flows", "0"],
        vec!["read", path, "--max-frame-bytes", "0"],
    ] {
        let output = run(&arguments);
        assert!(!output.status.success(), "{arguments:?}");
    }
}

// These commands intentionally name a public destination. Keep them in the
// feature profile where the CLI has no native I/O implementation to invoke.
#[cfg(not(any(
    feature = "native-route",
    feature = "native-layer2",
    feature = "native-layer3"
)))]
#[test]
fn dst_bearing_behind_policy() {
    let commands: &[&[&str]] = &[
        &[
            "--output",
            "json",
            "plan",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
        ],
        &[
            "--output",
            "json",
            "send",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
        ],
        &[
            "--output",
            "json",
            "exchange",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
        ],
        &["--output", "json", "scan", "8.8.8.8", "--ports", "80"],
        &[
            "--output",
            "json",
            "traceroute",
            "8.8.8.8",
            "--strategy",
            "icmp",
            "--max-hops",
            "1",
            "--attempts",
            "1",
        ],
        &[
            "--output",
            "json",
            "fuzz",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--cases",
            "1",
            "--live",
        ],
        &[
            "--output",
            "json",
            "dns",
            "8.8.8.8",
            "example.com",
            "--transaction-id",
            "7",
            "--source-port",
            "49152",
        ],
    ];

    for arguments in commands {
        let output = run(arguments);
        assert_eq!(
            output.status.code(),
            Some(6),
            "{arguments:?}: {:?}",
            output.stderr
        );
        let value = parse_json(&output);
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], "policy.public_destination");
    }
}

#[cfg(unix)]
#[test]
fn follow_write_through_alias_requested_paths() {
    let capture = write_capture();
    let root = tempfile::tempdir().expect("output root");
    let original = root.path().join("original");
    let alias = root.path().join("alias");
    std::fs::create_dir(&original).expect("output directory");
    std::os::unix::fs::symlink(&original, &alias).expect("directory alias");

    let output = run(&[
        "--output",
        "json",
        "follow",
        path_text(capture.path()),
        "--stream",
        "tcp:0",
        "--write",
        path_text(&alias),
    ]);
    assert!(output.status.success(), "{output:?}");
    let report = parse_json(&output);

    let written = report["result"]["written"]
        .as_array()
        .expect("written files");
    assert_eq!(written.len(), 2, "{report}");
    for (file, name) in written.iter().zip(["tcp-0-client.bin", "tcp-0-server.bin"]) {
        assert_eq!(file["path"], alias.join(name).display().to_string());
        assert!(
            original.join(name).is_file(),
            "{name} published in the target"
        );
    }
    assert!(
        !std::fs::read(original.join("tcp-0-client.bin"))
            .unwrap()
            .is_empty()
    );
    assert_eq!(std::fs::read_dir(&original).unwrap().count(), 2);
}
