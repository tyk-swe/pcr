// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Expert analysis gate contracts: the `--fail-on`/`--allow-findings`/
//! `--minimum-frames` CI gate counts every produced finding (before report
//! selectors and retention), evaluates only a completed run, and maps the
//! verdict onto process status. Pass exits 0; fail and inconclusive exit 1
//! after a normal completed report publishes. No `--fail-on` preserves the
//! legacy report-only behavior with `gate: null`.

use std::process::Command;

mod common;
#[path = "common/process.rs"]
mod process_support;

use common::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success};
use process_support::{decode_hex, run_with_stdin};

/// Clean UDP request/response pair (no findings).
const UDP_CLIENT: &str = "450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f";
const UDP_SERVER: &str = "450000210000000040118e95c6336402c000020100093039000d957e776f726c64";
/// Five-frame capture producing one error finding (`tcp.retransmission_conflicting`).
const TCP_CLIENT: &str =
    "4500002b0000000040068e96c0000201c63364023039005000000001000000005002ffffb7b80000676574";
const TCP_SERVER: &str =
    "450000280000000040068e99c6336402c0000201005030390000000a000000045012100083040000";
const TCP_DATA: &str =
    "4500002b0000000040068e96c0000201c633640230390050000000040000000b50181000be970000616263";
/// Out-of-order TCP flow leaving 2 pending bytes at EOF: warning
/// `tcp.previous_segment_not_captured` + info `tcp.incomplete_at_end`.
const TCP_SYN: &str =
    "450000280000000040068e99c0000201c63364029c4001bb0000006400000000500203e821640000";
const TCP_SYNACK: &str =
    "450000280000000040068e99c6336402c000020101bb9c40000001f400000065501203e81f5f0000";
const TCP_DATA_ABC: &str =
    "4500002b0000000040068e96c0000201c63364029c4001bb00000065000001f5501003e85afa0000616263";
const TCP_GAP_XY: &str =
    "4500002a0000000040068e97c0000201c63364029c4001bb0000006a000001f5501003e8a6df00007879";
/// Non-TCP tail frame; filtered out under `--filter tcp` while remaining the
/// final physical frame the EOF finding attributes to.
const UDP_TAIL: &str = "4500001e0000000040118e98c0000201c6336402c350270f000ac0d96869";
/// IPv4 fragment set: two completing frames + one datagram left incomplete;
/// produces IP lifecycle evidence but no expert findings.
const IPV4_FRAGMENT_FIRST: &str =
    "45000024002a200040116e68c0000201c63364029c40270f001800006162636465666768";
const IPV4_FRAGMENT_LAST: &str = "4500001c002a000240118e6ec0000201c6336402696a6b6c6d6e6f70";
const IPV4_FRAGMENT_INCOMPLETE: &str =
    "45000024002b200040116e67c0000201c63364029c40270f001800006162636465666768";

/// One PCAP record: (seconds, micros, captured_len, original_len, frame hex).
type Record = (u32, u32, u32, u32, String);

fn record(seconds: u32, frame: &str) -> Record {
    let len = u32::try_from(decode_hex(frame).len()).expect("fixture frame fits u32");
    (seconds, 250_000, len, len, frame.to_owned())
}

/// A record whose captured length is short of the wire length: the reader
/// emits `capture.frame_truncated` and the dissector emits
/// `decode.malformed_layer` for the truncated tail.
fn truncated_record(seconds: u32, frame: &str, drop_bytes: usize) -> Record {
    let bytes = decode_hex(frame);
    let captured = u32::try_from(bytes.len() - drop_bytes).expect("captured length fits u32");
    (
        seconds,
        250_000,
        captured,
        u32::try_from(bytes.len()).expect("original length fits u32"),
        frame.to_owned(),
    )
}

fn write_pcap(records: &[Record]) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    file.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, // little-endian microsecond PCAP
        2, 0, 4, 0, // version 2.4
        0, 0, 0, 0, 0, 0, 0, 0, // timezone and accuracy
        0xff, 0xff, 0, 0, // snap length
        228, 0, 0, 0, // DLT_IPV4
    ])
    .expect("global header must write");
    for (seconds, micros, captured, original, hex) in records {
        let bytes = decode_hex(hex);
        file.write_all(&seconds.to_le_bytes()).unwrap();
        file.write_all(&micros.to_le_bytes()).unwrap();
        file.write_all(&captured.to_le_bytes()).unwrap();
        file.write_all(&original.to_le_bytes()).unwrap();
        file.write_all(&bytes[..*captured as usize]).unwrap();
    }
    file.flush().expect("capture must flush");
    file
}

/// One error finding over five matched frames.
fn basic_capture() -> tempfile::NamedTempFile {
    write_pcap(&[
        record(1, UDP_CLIENT),
        record(2, UDP_SERVER),
        record(3, TCP_CLIENT),
        record(4, TCP_SERVER),
        record(5, TCP_DATA),
    ])
}

/// Warning on the gap frame plus an EOF info finding for the pending bytes.
fn gap_capture() -> tempfile::NamedTempFile {
    write_pcap(&[
        record(1, TCP_SYN),
        record(2, TCP_SYNACK),
        record(3, TCP_DATA_ABC),
        record(4, TCP_GAP_XY),
    ])
}

/// The gap flow plus a non-TCP tail frame: under `--filter tcp` the tail is
/// excluded while remaining the final physical frame the EOF finding
/// attributes to.
fn gap_tail_capture() -> tempfile::NamedTempFile {
    write_pcap(&[
        record(1, TCP_SYN),
        record(2, TCP_SYNACK),
        record(3, TCP_DATA_ABC),
        record(4, TCP_GAP_XY),
        record(5, UDP_TAIL),
    ])
}

/// {1 info, 2 warnings, 1 error} over six matched frames: the trigger counts
/// are 4 / 3 / 1 for fail-on info / warning / error.
fn mixed_severity_capture() -> tempfile::NamedTempFile {
    let malformed = TCP_DATA_ABC[..60].to_owned(); // cuts mid-TCP, caplen == origlen
    write_pcap(&[
        record(1, TCP_SYN),
        record(2, TCP_SYNACK),
        record(3, TCP_DATA_ABC),
        record(4, TCP_GAP_XY),
        record(100, &malformed),
        record(50, UDP_CLIENT), // regresses below the 100s high-water mark
    ])
}

/// Three findings over two frames: frame 1 truncates (warning + error),
/// frame 2 regresses the clock (warning). With `--max-frames 2` the aggregate
/// retention ceiling drops a finding while the gate still counts all three.
fn multi_finding_two_frame_capture() -> tempfile::NamedTempFile {
    write_pcap(&[
        truncated_record(100, UDP_SERVER, 5),
        record(50, UDP_CLIENT), // regresses below the 100s high-water mark
    ])
}

fn fragment_capture() -> tempfile::NamedTempFile {
    write_pcap(&[
        record(1, IPV4_FRAGMENT_FIRST),
        record(2, IPV4_FRAGMENT_LAST),
        record(3, IPV4_FRAGMENT_INCOMPLETE),
    ])
}

fn empty_capture() -> tempfile::NamedTempFile {
    write_pcap(&[])
}

fn gate_of(value: &serde_json::Value) -> &serde_json::Value {
    &value["result"]["gate"]
}

/// The full gate report a case expects, in the schema's field order.
struct ExpectedGate<'a> {
    verdict: &'a str,
    reason: &'a str,
    min_severity: &'a str,
    allow_findings: u64,
    minimum_frames: u64,
    frames_matched: u64,
    findings_observed: u64,
    triggering_findings: u64,
}

fn assert_gate(gate: &serde_json::Value, expected: ExpectedGate<'_>) {
    let fields = [
        ("verdict", serde_json::json!(expected.verdict)),
        ("reason", serde_json::json!(expected.reason)),
        ("min_severity", serde_json::json!(expected.min_severity)),
        ("allow_findings", serde_json::json!(expected.allow_findings)),
        ("minimum_frames", serde_json::json!(expected.minimum_frames)),
        ("frames_matched", serde_json::json!(expected.frames_matched)),
        (
            "findings_observed",
            serde_json::json!(expected.findings_observed),
        ),
        (
            "triggering_findings",
            serde_json::json!(expected.triggering_findings),
        ),
    ];
    for (field, value) in fields {
        assert_eq!(gate[field], value, "gate.{field}");
    }
}

// EG01 — no --fail-on: legacy report-only run, exit 0, gate stays null.
#[test]
fn absent_fail_on_preserves_report_only_behavior_and_null_gate() {
    for capture in [basic_capture(), empty_capture()] {
        let path = path_text(capture.path());
        for format in ["json", "ndjson", "text"] {
            let output = run_success(&["--output", format, "expert", path]);
            match format {
                "json" => assert!(parse_json(&output)["result"]["gate"].is_null()),
                "ndjson" => {
                    let records = parse_ndjson(&output);
                    assert_contiguous(&records);
                    assert_eq!(
                        records.iter().filter(|r| r["event"] == "complete").count(),
                        1,
                        "exactly one terminal complete"
                    );
                    assert!(records.last().unwrap()["result"]["gate"].is_null());
                }
                _ => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(!stdout.contains("gate="), "text: {stdout}");
                }
            }
        }
    }
}

// EG02 — {1 info, 2 warnings, 1 error}; trigger counts 4/3/1, observed 4.
#[test]
fn gate_counts_every_finding_once_per_threshold() {
    let capture = mixed_severity_capture();
    let path = path_text(capture.path());
    for (severity, triggering) in [("info", 4), ("warning", 3), ("error", 1)] {
        let output = run(&["--output", "json", "expert", path, "--fail-on", severity]);
        assert_eq!(output.status.code(), Some(1), "{severity}: {output:?}");
        let value = parse_json(&output);
        assert_gate(
            gate_of(&value),
            ExpectedGate {
                verdict: "fail",
                reason: "finding_allowance_exceeded",
                min_severity: severity,
                allow_findings: 0,
                minimum_frames: 1,
                frames_matched: 6,
                findings_observed: 4,
                triggering_findings: triggering,
            },
        );
    }
}

// EG03 — allowance boundary: below, equal, and above the trigger count.
#[test]
fn allowance_boundary_passes_at_equality_and_fails_above() {
    let capture = basic_capture();
    let path = path_text(capture.path());
    // One error finding; error gate triggering = 1.
    for (allowance, verdict, code) in [(2, "pass", 0), (1, "pass", 0), (0, "fail", 1)] {
        let allow = allowance.to_string();
        let output = run(&[
            "--output",
            "json",
            "expert",
            path,
            "--fail-on",
            "error",
            "--allow-findings",
            &allow,
        ]);
        assert_eq!(
            output.status.code(),
            Some(code),
            "allowance {allowance}: {output:?}"
        );
        assert_eq!(gate_of(&parse_json(&output))["verdict"], verdict);
    }
}

// EG04 — coverage boundary: below, equal, and above the minimum.
#[test]
fn minimum_frames_boundary_inconclusive_below_and_passes_at_equality() {
    let capture = basic_capture();
    let path = path_text(capture.path());
    // One error finding; --allow-findings 1 leaves coverage as the decider.
    for (minimum, verdict, code) in [(6, "inconclusive", 1), (5, "pass", 0), (4, "pass", 0)] {
        let min = minimum.to_string();
        let output = run(&[
            "--output",
            "json",
            "expert",
            path,
            "--fail-on",
            "error",
            "--allow-findings",
            "1",
            "--minimum-frames",
            &min,
        ]);
        assert_eq!(
            output.status.code(),
            Some(code),
            "minimum {minimum}: {output:?}"
        );
        assert_eq!(gate_of(&parse_json(&output))["verdict"], verdict);
    }
}

// EG05 — excess findings and insufficient coverage: the violation wins.
#[test]
fn allowance_violation_wins_over_insufficient_coverage() {
    let capture = basic_capture();
    let path = path_text(capture.path());
    let output = run(&[
        "--output",
        "json",
        "expert",
        path,
        "--fail-on",
        "error",
        "--minimum-frames",
        "10",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_gate(
        gate_of(&parse_json(&output)),
        ExpectedGate {
            verdict: "fail",
            reason: "finding_allowance_exceeded",
            min_severity: "error",
            allow_findings: 0,
            minimum_frames: 10,
            frames_matched: 5,
            findings_observed: 1,
            triggering_findings: 1,
        },
    );
}

// EG06 — empty capture and zero-matching filters are inconclusive, not failed.
#[test]
fn empty_match_set_with_gate_is_inconclusive_with_completed_report() {
    let empty = empty_capture();
    let output = run(&[
        "--output",
        "json",
        "expert",
        path_text(empty.path()),
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let value = parse_json(&output);
    assert_eq!(value["status"], "success");
    assert_gate(
        gate_of(&value),
        ExpectedGate {
            verdict: "inconclusive",
            reason: "insufficient_frames",
            min_severity: "info",
            allow_findings: 0,
            minimum_frames: 1,
            frames_matched: 0,
            findings_observed: 0,
            triggering_findings: 0,
        },
    );

    let gap = gap_capture();
    let output = run(&[
        "--output",
        "ndjson",
        "expert",
        path_text(gap.path()),
        "--filter",
        "udp",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    let complete = records.last().unwrap();
    assert_eq!(complete["event"], "complete");
    assert_eq!(complete["status"], "success");
    assert_eq!(complete["result"]["gate"]["verdict"], "inconclusive");
}

// EG07 — report selectors hide findings; the gate still counts and fails.
#[test]
fn selector_hidden_findings_still_fail_the_gate() {
    let capture = gap_capture();
    let path = path_text(capture.path());
    // --min-severity error hides both findings from the report.
    let output = run(&[
        "--output",
        "json",
        "expert",
        path,
        "--min-severity",
        "error",
        "--fail-on",
        "warning",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let value = parse_json(&output);
    assert_eq!(value["result"]["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["result"]["errors"], 0);
    assert_eq!(value["result"]["warnings"], 0);
    assert_gate(
        gate_of(&value),
        ExpectedGate {
            verdict: "fail",
            reason: "finding_allowance_exceeded",
            min_severity: "warning",
            allow_findings: 0,
            minimum_frames: 1,
            frames_matched: 4,
            findings_observed: 2,
            triggering_findings: 1,
        },
    );

    // A misspelled --code hides the detail but cannot suppress the verdict.
    let output = run(&[
        "--output",
        "json",
        "expert",
        path,
        "--code",
        "tcp.not_a_real_code",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let value = parse_json(&output);
    assert_eq!(value["result"]["findings"].as_array().unwrap().len(), 0);
    assert_eq!(value["result"]["gate"]["triggering_findings"], 2);
}

// EG08 — multiple findings in one frame count individually; retention
// omission affects report details/diagnostics, never gate counts.
#[test]
fn multi_finding_frames_and_retention_omission_keep_gate_counts_exact() {
    let capture = multi_finding_two_frame_capture();
    let path = path_text(capture.path());
    // Three findings over two frames; retention ceiling = --max-frames = 2.
    let output = run(&[
        "--output",
        "json",
        "expert",
        path,
        "--max-frames",
        "2",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let value = parse_json(&output);
    assert_eq!(
        value["result"]["findings"].as_array().unwrap().len(),
        2,
        "retention drops one finding"
    );
    assert!(
        value["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["code"] == "expert.findings_omitted"),
        "omission diagnostic surfaces: {value}"
    );
    assert_gate(
        gate_of(&value),
        ExpectedGate {
            verdict: "fail",
            reason: "finding_allowance_exceeded",
            min_severity: "info",
            allow_findings: 0,
            minimum_frames: 1,
            frames_matched: 2,
            findings_observed: 3,
            triggering_findings: 3,
        },
    );
    // Selected counters still count every selected finding (retention ≠ selection).
    assert_eq!(value["result"]["errors"], 1);
    assert_eq!(value["result"]["warnings"], 2);
}

// EG09 — the trailing EOF finding reaches the gate before evaluation:
// without it, triggering would be 1 and this run would pass.
#[test]
fn eof_trailing_finding_is_counted_before_gate_evaluation() {
    let capture = gap_capture();
    let path = path_text(capture.path());
    let output = run(&[
        "--output",
        "json",
        "expert",
        path,
        "--fail-on",
        "info",
        "--allow-findings",
        "1",
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let value = parse_json(&output);
    assert_eq!(value["result"]["gate"]["findings_observed"], 2);
    assert_eq!(value["result"]["gate"]["triggering_findings"], 2);
    assert_eq!(value["result"]["gate"]["verdict"], "fail");
}

// EG10 — dependency and range validation fires before capture I/O:
// every failure below is a usage error (2), never a capture error (3).
#[test]
fn gate_flags_validate_before_input_opens() {
    let missing = "/nonexistent/capture.pcap";
    for arguments in [
        vec!["expert", missing, "--allow-findings", "0"],
        vec!["expert", missing, "--allow-findings", "3"],
        vec!["expert", missing, "--minimum-frames", "5"],
        vec!["expert", missing, "--minimum-frames", "0"],
        vec![
            "expert",
            missing,
            "--fail-on",
            "warning",
            "--minimum-frames",
            "0",
        ],
        vec!["expert", missing, "--fail-on", "not-a-severity"],
        vec![
            "expert",
            missing,
            "--fail-on",
            "warning",
            "--allow-findings",
            "18446744073709551616",
        ],
        vec![
            "expert",
            missing,
            "--fail-on",
            "warning",
            "--minimum-frames",
            "18446744073709551616",
        ],
    ] {
        let output = run(&arguments);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{arguments:?} must fail as usage before input opens: {output:?}"
        );
    }
}

// EG11 — execution failures keep their classification and publish no
// completed gate: malformed capture, resource ceiling, analysis limit,
// duration deadline.
#[test]
fn execution_failures_publish_no_completed_gate() {
    // Malformed capture: packet read failure.
    let mut capture = basic_capture();
    process_support::append_truncated_record(&mut capture);
    for format in ["json", "ndjson"] {
        let output = run(&[
            "--output",
            format,
            "expert",
            path_text(capture.path()),
            "--fail-on",
            "warning",
        ]);
        assert_eq!(output.status.code(), Some(3), "{format}: {output:?}");
        match format {
            "json" => {
                let value = parse_json(&output);
                assert_eq!(value["status"], "error");
                assert!(value["result"].is_null() || value.get("result").is_none());
            }
            _ => {
                let records = parse_ndjson(&output);
                assert_contiguous(&records);
                assert_eq!(records.last().unwrap()["event"], "error");
                assert!(
                    records.iter().all(|r| r["event"] != "complete"),
                    "no completed report after a read failure"
                );
            }
        }
    }

    // Resource ceiling: --max-frames below the physical frame count is a
    // policy failure (6), not a verdict.
    let gap = gap_capture();
    let output = run(&[
        "--output",
        "json",
        "expert",
        path_text(gap.path()),
        "--max-frames",
        "2",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let value = parse_json(&output);
    assert_eq!(value["status"], "error");

    // Analysis limit validation: invalid bound is a usage failure.
    let output = run(&[
        "--output",
        "json",
        "expert",
        path_text(gap.path()),
        "--max-flows",
        "0",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");

    // Duration deadline: the run dies as policy.duration_limit, not a verdict.
    let output = run(&[
        "--output",
        "json",
        "expert",
        path_text(gap.path()),
        "--max-duration-ms",
        "0",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let value = parse_json(&output);
    assert_eq!(value["status"], "error");
}

// EG12 — all three verdicts publish consistently across text/JSON/NDJSON:
// contiguous sequences, exactly one terminal complete, no complete→error.
#[test]
fn verdicts_publish_consistently_across_all_formats() {
    let gap = gap_capture();
    let path = path_text(gap.path());
    let cases: &[(&[&str], &str, i32)] = &[
        (&["--fail-on", "error"], "pass", 0),
        (&["--fail-on", "info"], "fail", 1),
        (
            &["--fail-on", "error", "--minimum-frames", "10"],
            "inconclusive",
            1,
        ),
    ];
    for (flags, verdict, code) in cases {
        for format in ["json", "ndjson", "text"] {
            let mut arguments = vec!["--output", format, "expert", path];
            arguments.extend(flags.iter());
            let output = run(&arguments);
            assert_eq!(
                output.status.code(),
                Some(*code),
                "{format} {flags:?}: {output:?}"
            );
            match format {
                "json" => {
                    let value = parse_json(&output);
                    assert_eq!(value["status"], "success", "{flags:?}");
                    assert_eq!(value["result"]["gate"]["verdict"], *verdict);
                }
                "ndjson" => {
                    let records = parse_ndjson(&output);
                    assert_contiguous(&records);
                    assert_eq!(
                        records.iter().filter(|r| r["event"] == "complete").count(),
                        1,
                        "exactly one terminal complete for {flags:?}"
                    );
                    assert_eq!(records.last().unwrap()["event"], "complete");
                    assert!(
                        records.iter().all(|r| r["event"] != "error"),
                        "no error record follows a completed verdict"
                    );
                    assert_eq!(
                        records.last().unwrap()["result"]["gate"]["verdict"],
                        *verdict
                    );
                }
                _ => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let gate_line = stdout
                        .lines()
                        .last()
                        .expect("text output ends with the gate line");
                    assert!(
                        gate_line.starts_with(&format!("gate={verdict} reason=")),
                        "{format} {flags:?}: {gate_line}"
                    );
                }
            }
        }
    }
}

// EG13 — a broken sink beats the would-be verdict status: io failure (5)
// wins over fail (1) and pass (0) alike.
#[cfg(packetcraftr_test_dev_full)]
#[test]
fn broken_output_overrides_verdict_exit_status() {
    common::require_dev_full();
    let capture = gap_capture();
    let path = path_text(capture.path()).to_owned();
    for (flags, format) in [
        (vec!["--fail-on", "info"], "json"),
        (vec!["--fail-on", "error"], "json"),
        (vec!["--fail-on", "info"], "ndjson"),
        (vec!["--fail-on", "info"], "text"),
    ] {
        let mut arguments = vec!["--output", format, "expert", path.as_str()];
        arguments.extend(flags.iter().copied());
        let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(&arguments)
            .stdout(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .expect("/dev/full must be writable"),
            )
            .output()
            .expect("CLI process must start");
        assert_eq!(
            output.status.code(),
            Some(5),
            "{arguments:?}: output failure must beat the verdict status"
        );
    }
}

// EG14 — the analysis domain is preserved: filters, epoch bounds, derived
// datagrams, compressed input, and stdin all feed the same gate.
#[test]
fn analysis_domain_inputs_feed_the_same_gate() {
    let gap_tail = gap_tail_capture();
    let tail_path = path_text(gap_tail.path());

    // Stream-aware filter: pending flow still completes; gate still fails.
    let output = run(&[
        "--output",
        "json",
        "expert",
        tail_path,
        "--filter",
        "tcp.stream == 0",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(gate_of(&parse_json(&output))["verdict"], "fail");

    // Epoch bounds narrow the matched domain to a mid-flow window: frames
    // 3-4 (the gap pair) match; the bounded run still produces its warning
    // and EOF finding and the gate still fails on them.
    let output = run(&[
        "--output",
        "json",
        "expert",
        tail_path,
        "--start-epoch",
        "3",
        "--stop-epoch",
        "5",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let value = parse_json(&output);
    assert_eq!(value["result"]["frames_matched"], 2);
    assert_gate(
        gate_of(&value),
        ExpectedGate {
            verdict: "fail",
            reason: "finding_allowance_exceeded",
            min_severity: "info",
            allow_findings: 0,
            minimum_frames: 1,
            frames_matched: 2,
            findings_observed: 2,
            triggering_findings: 2,
        },
    );

    // stdin input.
    let bytes = std::fs::read(gap_tail.path()).expect("capture bytes");
    let output = run_with_stdin(
        &["--output", "json", "expert", "-", "--fail-on", "warning"],
        &bytes,
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(gate_of(&parse_json(&output))["verdict"], "fail");

    // Compressed input: gzip member detected by magic, same verdict.
    let compressed = run_success(&[
        "--output",
        "pcap",
        "read",
        tail_path,
        "--compression",
        "gzip",
    ]);
    let gz = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(gz.path(), &compressed.stdout).unwrap();
    let output = run(&[
        "--output",
        "json",
        "expert",
        path_text(gz.path()),
        "--fail-on",
        "warning",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(gate_of(&parse_json(&output))["verdict"], "fail");

    // Derived datagrams produce IP evidence without synthetic physical frames.
    let frags = fragment_capture();
    let output = run(&[
        "--output",
        "ndjson",
        "expert",
        path_text(frags.path()),
        "--fail-on",
        "info",
    ]);
    assert!(output.status.success(), "{output:?}");
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    assert!(
        records
            .iter()
            .any(|r| r["event"] == "ip_datagram_incomplete")
    );
    let complete = records.last().unwrap();
    assert_eq!(complete["result"]["frames_matched"], 3);
    assert_eq!(complete["result"]["gate"]["verdict"], "pass");
}

// EG15 — the filter excludes the tail frame but not the pending flow's
// pushes: the EOF finding attributes to the final physical frame (5, the
// filtered-out UDP tail) and still reaches the gate.
#[test]
fn filtered_tail_frame_keeps_eof_attribution_and_gate_counts_it() {
    let capture = gap_tail_capture();
    let path = path_text(capture.path());

    // Info gate fails: the EOF info finding triggers it.
    let output = run(&[
        "--output",
        "json",
        "expert",
        path,
        "--filter",
        "tcp",
        "--fail-on",
        "info",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let value = parse_json(&output);
    assert_eq!(value["result"]["frames_matched"], 4);
    assert_eq!(value["result"]["frames_read"], 5);
    assert_gate(
        gate_of(&value),
        ExpectedGate {
            verdict: "fail",
            reason: "finding_allowance_exceeded",
            min_severity: "info",
            allow_findings: 0,
            minimum_frames: 1,
            frames_matched: 4,
            findings_observed: 2,
            triggering_findings: 2,
        },
    );
    let eof = value["result"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["code"] == "tcp.incomplete_at_end")
        .expect("EOF finding present");
    assert_eq!(
        eof["frame"], 5,
        "EOF finding attributes to the final physical input frame"
    );
    assert_eq!(
        eof["stream"], 0,
        "pending flow resolves to its conversation"
    );

    // Warning gate with an allowance for the single warning: coverage
    // requirement makes it inconclusive rather than failed.
    let output = run(&[
        "--output",
        "json",
        "expert",
        path,
        "--filter",
        "tcp",
        "--fail-on",
        "warning",
        "--allow-findings",
        "1",
        "--minimum-frames",
        "5",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_gate(
        gate_of(&parse_json(&output)),
        ExpectedGate {
            verdict: "inconclusive",
            reason: "insufficient_frames",
            min_severity: "warning",
            allow_findings: 1,
            minimum_frames: 5,
            frames_matched: 4,
            findings_observed: 2,
            triggering_findings: 1,
        },
    );
}

// EG16 — incomplete IP-only evidence without expert findings passes the gate.
#[test]
fn incomplete_ip_evidence_without_findings_passes() {
    let capture = fragment_capture();
    let path = path_text(capture.path());
    let output = run_success(&["--output", "json", "expert", path, "--fail-on", "info"]);
    let value = parse_json(&output);
    assert_eq!(value["result"]["findings"].as_array().unwrap().len(), 0);
    assert_gate(
        gate_of(&value),
        ExpectedGate {
            verdict: "pass",
            reason: "within_allowance",
            min_severity: "info",
            allow_findings: 0,
            minimum_frames: 1,
            frames_matched: 3,
            findings_observed: 0,
            triggering_findings: 0,
        },
    );
    // The incomplete datagram stays visible as separate IP evidence.
    let families = value["result"]["ip_reassembly"]["families"]
        .as_array()
        .unwrap();
    assert!(
        families
            .iter()
            .any(|f| f["incomplete_datagrams"].as_u64().unwrap_or(0) >= 1),
        "incomplete IP evidence remains visible: {value}"
    );
}

// Cancellation before publication: exit 130 and no completed gate is
// fabricated. Gated on procfs/kill like the cancellation suite.
#[cfg(packetcraftr_test_procfs)]
#[test]
fn cancellation_before_publication_fabricates_no_completed_gate() {
    use std::io::Write;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    common::require_procfs();
    let capture = gap_capture();
    let bytes = std::fs::read(capture.path()).unwrap();
    let stdout_file = tempfile::NamedTempFile::new().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(["--output", "text", "expert", "-", "--fail-on", "info"])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(stdout_file.reopen().unwrap()))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&bytes).unwrap();
    // Wait until the child is blocked reading stdin, then interrupt.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "child never blocked on stdin");
        let wchan =
            std::fs::read_to_string(format!("/proc/{}/wchan", child.id())).unwrap_or_default();
        if wchan.contains("pipe_read") {
            break;
        }
        assert!(child.try_wait().unwrap().is_none(), "child exited early");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        Command::new("kill")
            .args(["-s", "INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    std::thread::sleep(Duration::from_millis(100));
    drop(stdin); // release the blocked read; cancellation fires next check

    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline + Duration::from_secs(5),
            "interrupted child did not stop"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(130));
    let captured = std::fs::read(stdout_file.path()).unwrap();
    let stdout = String::from_utf8_lossy(&captured);
    assert!(
        !stdout.contains("gate=") && !stdout.contains("finding(s) ("),
        "no completed gate or summary may be fabricated: {stdout}"
    );
}
