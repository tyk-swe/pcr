// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{path_text, run};

const TCP_SESSION_RECIPE: &str = "ethernet(src=02:00:00:00:00:01,dst=02:00:00:00:00:02)/ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=40000,dport=80)/raw()";

#[test]
fn build_session_reports_the_frame_limit_and_empty_responses_as_typed_errors() {
    let output = run(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "tcp",
        "--packet",
        "ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=40000,dport=80)/raw(text=hello)",
        "--link-type",
        "ipv4",
        "--session-mss",
        "1",
        "--max-template-packets",
        "10",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cli.conversation_limit"));

    let directory = tempfile::tempdir().expect("scratch directory");
    let empty = directory.path().join("empty.bin");
    std::fs::write(&empty, b"").unwrap();
    let output = run(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "tcp",
        "--packet",
        TCP_SESSION_RECIPE,
        "--link-type",
        "ethernet",
        "--session-response-file",
        path_text(&empty),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("response file"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("is empty"));
}

#[test]
fn build_session_refuses_oversized_or_conflicting_requests_before_output() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let response = directory.path().join("response.bin");
    std::fs::write(&response, vec![0_u8; 1460 * 5000]).unwrap();
    for extra in [
        &["--session-response-file", path_text(&response)][..],
        &["--max-template-packets", "5"][..],
        &["--axis", "1.dport=[80,81]"][..],
        &["--session-mss", "0"][..],
    ] {
        let mut arguments = vec![
            "--output",
            "pcap",
            "build",
            "--session",
            "tcp",
            "--packet",
            TCP_SESSION_RECIPE,
            "--link-type",
            "ethernet",
        ];
        arguments.extend_from_slice(extra);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{extra:?}");
        assert!(output.stdout.is_empty(), "{extra:?}");
    }
    // Session options without --session, and the step without capture output.
    for arguments in [
        &[
            "--output",
            "ndjson",
            "build",
            "--packet",
            TCP_SESSION_RECIPE,
            "--session-mss",
            "100",
        ][..],
        &[
            "--output",
            "ndjson",
            "build",
            "--session",
            "tcp",
            "--packet",
            TCP_SESSION_RECIPE,
            "--session-step-ns",
            "5",
        ][..],
    ] {
        let output = run(arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        // NDJSON reports the error as its one record, never as a packet event.
        assert!(!String::from_utf8_lossy(&output.stdout).contains("\"event\":\"packet\""));
    }
    let output = run(&[
        "--output",
        "pcap",
        "build",
        "--session",
        "udp",
        "--packet",
        "ethernet()/ipv4()/udp()",
        "--link-type",
        "ethernet",
        "--session-mss",
        "100",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--session tcp"));
}

#[test]
fn build_enforces_layer_limit_before_decoding_later_layers() {
    let output = run(&[
        "--output",
        "json",
        "build",
        "--max-layers",
        "1",
        "--packet",
        "raw()/not_a_protocol()",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let report = common::parse_json(&output);
    assert_eq!(report["error"]["code"], "cli.expression_limit");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("unknown protocol"));
}

#[test]
fn build_document_enforces_layer_limit_before_protocol_conversion() {
    let directory = tempfile::tempdir().unwrap();
    let recipe = directory.path().join("packet.json");
    std::fs::write(&recipe, r#"{"schema":"packetcraftr.packet/v2","layers":[{"protocol":"raw","fields":{}},{"protocol":"not_a_protocol","fields":{}}]}"#).unwrap();
    let output = run(&[
        "--output",
        "json",
        "build",
        "--max-layers",
        "1",
        "--packet-file",
        path_text(&recipe),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        common::parse_json(&output)["error"]["code"],
        "cli.document_limit"
    );
}
