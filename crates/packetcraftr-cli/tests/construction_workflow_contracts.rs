// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{path_text, run};

const TCP_SESSION_RECIPE: &str = "ethernet(src=02:00:00:00:00:01,dst=02:00:00:00:00:02)/ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=40000,dport=80)/raw()";

#[test]
fn build_session_reports_limit_empty_errors() {
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
fn build_session_reject_before_output() {
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
