// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::capture_support;
use crate::common;

use capture_support::{ethernet_frame, write_pcapng};
use common::{parse_json, path_text, run, run_success};

fn examples() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn tcp_capture(path: &std::path::Path, count: usize) {
    use packetcraftr_core::{frame::LinkType, protocol::transport::Tcp};
    let tcp = Tcp {
        source_port: 40000,
        destination_port: 80,
        ..Default::default()
    };
    write_pcapng(
        path,
        LinkType::ETHERNET,
        &vec![ethernet_frame(tcp, 24); count],
    );
}

#[test]
fn v1_rules_file_rejects_unknown_assignment_properties() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules.json");
    let target = directory.path().join("edited.pcapng");
    let document = serde_json::json!({
        "schema": "packetcraftr.rewrite/v1",
        "rules": [{"assign": [{"field": "ipv4.ttl", "value": 63, "occurrence": 2}]}],
    });
    std::fs::write(&rules, serde_json::to_vec(&document).unwrap()).unwrap();

    let output = run(&[
        "files",
        "rewrite",
        path_text(&source),
        "--rules-file",
        path_text(&rules),
        "--write",
        path_text(&target),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid rewrite rules"));
    assert!(!target.exists());
}

#[test]
fn change_reporting_is_bounded_and_discloses_omissions() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("many.pcapng");
    tcp_capture(&source, 1100);
    let target = directory.path().join("edited.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "files",
        "rewrite",
        path_text(&source),
        "--set",
        "ipv4.ttl=63",
        "--set",
        "tcp.sequence=9",
        "--set",
        "tcp.acknowledgment=9",
        "--write",
        path_text(&target),
    ]));
    assert_eq!(report["result"]["changes"].as_array().unwrap().len(), 4096);
    assert!(report["result"]["changes_omitted"].as_u64().unwrap() > 0);
}
