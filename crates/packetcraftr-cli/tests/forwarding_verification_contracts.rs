// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{Record, UDP_CLIENT, write_pcap_hex, write_records};
use common::{parse_json, path_text, run};
use process_support::decode_hex;

/// `UDP_CLIENT` forwarded: TTL decremented to 63 with the checksum updated.
const UDP_CLIENT_FORWARDED: &str =
    "45000021000000003f118f95c0000201c633640230390009000d9f8868656c6c6f";

fn write_snaplen_truncated_capture() -> tempfile::NamedTempFile {
    let ipv4_header_only = 20;
    write_records(&[Record::truncated(
        (1, 250_000),
        decode_hex(UDP_CLIENT),
        ipv4_header_only,
    )])
}

fn verify(ingress: &tempfile::NamedTempFile, egress: &tempfile::NamedTempFile) -> Vec<String> {
    vec![
        "verify-forwarding".to_owned(),
        path_text(ingress.path()).to_owned(),
        path_text(egress.path()).to_owned(),
    ]
}

#[test]
fn an_empty_selection_never_passes() {
    let ingress = write_pcap_hex(&[UDP_CLIENT]);
    let egress = write_pcap_hex(&[UDP_CLIENT]);

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend([
        "--identity".to_owned(),
        "raw.bytes".to_owned(),
        "--egress-filter".to_owned(),
        "icmp".to_owned(),
    ]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "inconclusive");
    assert_eq!(result["captures"]["egress"]["selected"], 0);
    assert_eq!(result["summary"]["ingress_only"], 1);
}

#[test]
fn snaplen_truncated_evidence_is_explicitly_inconclusive() {
    let ingress = write_pcap_hex(&[UDP_CLIENT]);
    let egress = write_snaplen_truncated_capture();

    let mut args = vec!["--output".to_owned(), "json".to_owned()];
    args.extend(verify(&ingress, &egress));
    args.extend(["--identity".to_owned(), "raw.bytes".to_owned()]);
    let output = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(output.status.code(), Some(1));

    let result = parse_json(&output)["result"].clone();
    assert_eq!(result["verdict"], "inconclusive");
    assert_eq!(result["captures"]["egress"]["incomplete"], 1);
    assert_eq!(result["captures"]["egress"]["unkeyed"], 1);
    assert_eq!(result["unkeyed"]["egress"][0]["evidence"]["frame"], 1);
}

#[test]
fn malformed_expectations_are_rejected_before_input_is_read() {
    let output = run(&[
        "verify-forwarding",
        "does-not-exist.pcap",
        "also-absent.pcap",
        "--identity",
        "raw.bytes",
        "--expect",
        "no-equals-sign",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cli.verify_rule"), "{stderr}");
    assert!(!stderr.contains("does-not-exist"), "{stderr}");
}
