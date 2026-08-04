// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use super::super::support::{binary, write_capture};
use super::{built_frame, filterable_capture};

#[test]
fn stats_reports_conversations_protocols_and_io_over_a_capture() {
    let capture = filterable_capture();
    let stats = |arguments: &[&str]| -> String {
        let mut command = binary();
        command.arg("stats").arg(&capture).args(arguments);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };

    let conversations = stats(&["--table", "conversations"]);
    assert!(conversations.starts_with("matched 2 of 2 frame(s)"));
    assert!(conversations.contains("udp stream 0: 10.0.0.1:1000 <-> 10.0.0.2:53"));
    assert!(conversations.contains("tcp stream 0: 192.168.0.1:1000 <-> 192.168.0.2:443"));

    let protocols = stats(&["--table", "protocols"]);
    assert!(protocols.contains("ethernet: frames 2 (100.0%)"));
    assert!(protocols.contains("udp: frames 1 (50.0%)"));

    // Filtering narrows the tables while frame numbering stays capture-global.
    let filtered = stats(&["--table", "endpoints", "--filter", "tcp"]);
    assert!(filtered.starts_with("matched 1 of 2 frame(s)"));
    assert!(filtered.contains("192.168.0.1: tx 1 frame(s)"));
    assert!(!filtered.contains("10.0.0.1"));

    // Stream-aware filters are supported here, unlike frame-at-a-time
    // commands, because stats assigns conversation indices.
    let stream = stats(&["--table", "conversations", "--filter", "udp.stream == 0"]);
    assert!(stream.contains("udp stream 0"));
    assert!(!stream.contains("tcp stream"));

    let io = stats(&["--table", "io", "--interval-ms", "500"]);
    assert!(io.contains("+0ns: frames 1"));
}

#[test]
fn stats_rejects_unsupported_formats_and_invalid_limits_up_front() {
    let unsupported = binary()
        .args(["--output", "hex", "stats", "missing.pcap"])
        .output()
        .unwrap();
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unsupported.stderr).contains("does not support hex"),
        "{}",
        String::from_utf8_lossy(&unsupported.stderr)
    );

    let interval = binary()
        .args(["stats", "missing.pcap", "--interval-ms", "0"])
        .output()
        .unwrap();
    assert_eq!(interval.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&interval.stderr).contains("interval"),
        "{}",
        String::from_utf8_lossy(&interval.stderr)
    );
}

#[test]
fn stats_rejects_invalid_analysis_limits_before_opening_the_capture() {
    // The file does not exist; the limit error must still win.
    let output = binary()
        .args(["stats", "definitely-missing.pcap", "--max-flows", "0"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("max_flows"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// One TCP conversation exhibiting a retransmission, a duplicate
/// acknowledgment, and a reset, so `expert` has anomalies to report.
fn anomalous_capture() -> PathBuf {
    let data = built_frame(
        "ethernet/ipv4(source=10.0.0.1,destination=10.0.0.2)\
         /tcp(source_port=1000,destination_port=443,sequence=100,acknowledgment=0,\
         flags=16,window=512)/raw(text=data)",
    );
    let ack = built_frame(
        "ethernet/ipv4(source=10.0.0.2,destination=10.0.0.1)\
         /tcp(source_port=443,destination_port=1000,sequence=500,acknowledgment=100,\
         flags=16,window=512)",
    );
    let reset = built_frame(
        "ethernet/ipv4(source=10.0.0.2,destination=10.0.0.1)\
         /tcp(source_port=443,destination_port=1000,sequence=501,acknowledgment=0,\
         flags=4,window=0)",
    );
    write_capture(&[&data, &data, &ack, &ack, &reset], false)
}

#[test]
fn expert_reports_tcp_anomalies_over_a_capture() {
    let capture = anomalous_capture();
    let expert = |arguments: &[&str]| -> String {
        let mut command = binary();
        command.arg("expert").arg(&capture).args(arguments);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };

    let text = expert(&[]);
    assert!(
        text.contains("#2 Warning tcp.retransmission (tcp stream 0)"),
        "{text}"
    );
    assert!(
        text.contains("#4 Warning tcp.duplicate_ack (tcp stream 0)"),
        "{text}"
    );
    assert!(
        text.contains("#5 Warning tcp.reset (tcp stream 0)"),
        "{text}"
    );
    assert!(
        text.contains(
            "found 3 finding(s) (0 error(s), 3 warning(s), 0 note(s)) in 5 of 5 frame(s)"
        ),
        "{text}"
    );

    // NDJSON emits one record per finding plus a terminal summary, with
    // contiguous sequence numbers.
    let stream = expert(&["--output", "ndjson"]);
    assert_eq!(stream.lines().count(), 4);
    let sequences = stream
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap()["sequence"]
                .as_u64()
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(sequences, vec![0, 1, 2, 3]);
    assert!(stream.contains("\"frames_read\":5"));

    // Stream-aware filters are supported because expert assigns conversation
    // indices; frame numbering stays capture-global under a filter.
    let filtered = expert(&["--filter", "tcp.stream == 0"]);
    assert!(filtered.contains("#5 Warning tcp.reset"), "{filtered}");

    // A filter narrowing to the reset frame alone leaves no prior segments to
    // compare against, so only the reset itself is reported.
    let reset_only = expert(&["--filter", "tcp.flags.reset == 1"]);
    assert!(reset_only.contains("in 1 of 5 frame(s)"), "{reset_only}");
    assert!(!reset_only.contains("tcp.retransmission"), "{reset_only}");
}

#[test]
fn expert_rejects_unsupported_formats_and_invalid_limits_up_front() {
    let unsupported = binary()
        .args(["--output", "hex", "expert", "missing.pcap"])
        .output()
        .unwrap();
    assert_eq!(unsupported.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&unsupported.stderr).contains("does not support hex"),
        "{}",
        String::from_utf8_lossy(&unsupported.stderr)
    );

    // The file does not exist; the limit error must still win.
    let limits = binary()
        .args(["expert", "definitely-missing.pcap", "--max-flows", "0"])
        .output()
        .unwrap();
    assert_eq!(limits.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&limits.stderr).contains("max_flows"),
        "{}",
        String::from_utf8_lossy(&limits.stderr)
    );
}
