// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    CommandName, PathBuf, assert_gre_sctp_example, assert_igmp_example, binary, example, json_file,
};

#[test]
fn published_stats_outputs_match_the_cli() {
    // The success golden replays the committed conversation fixture; the
    // error golden is the deterministic filter refusal, which fires before
    // any input file is opened.
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/captures/pcap/tcp-udp-conversations.pcap");
    let success = binary()
        .args(["--output", "json", "stats"])
        .arg(&fixture)
        .args(["--table", "conversations"])
        .output()
        .unwrap();
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let actual: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(actual, json_file("output-stats-success.json"));

    let error = binary()
        .args([
            "--output",
            "json",
            "stats",
            "definitely-missing.pcap",
            "--filter",
            "nope == 1",
        ])
        .output()
        .unwrap();
    assert_eq!(error.status.code(), Some(2));
    let actual: serde_json::Value = serde_json::from_slice(&error.stdout).unwrap();
    assert_eq!(actual, json_file("output-stats-error.json"));
}

#[test]
fn published_expert_outputs_match_the_cli() {
    // The success golden replays the committed anomaly fixture, the event
    // golden is the first ndjson finding from the same run, and the error
    // golden is the deterministic filter refusal, which fires before any
    // input file is opened.
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/captures/pcap/tcp-anomalies.pcap");
    let success = binary()
        .args(["--output", "json", "expert"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let actual: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(actual, json_file("output-expert-success.json"));

    let stream = binary()
        .args(["--output", "ndjson", "expert"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(stream.status.success());
    let first = stream.stdout.split(|byte| *byte == b'\n').next().unwrap();
    let actual: serde_json::Value = serde_json::from_slice(first).unwrap();
    assert_eq!(actual, json_file("output-expert-event.json"));

    let error = binary()
        .args([
            "--output",
            "json",
            "expert",
            "definitely-missing.pcap",
            "--filter",
            "nope == 1",
        ])
        .output()
        .unwrap();
    assert_eq!(error.status.code(), Some(2));
    let actual: serde_json::Value = serde_json::from_slice(&error.stdout).unwrap();
    assert_eq!(actual, json_file("output-expert-error.json"));
}

#[test]
fn published_follow_outputs_match_the_cli() {
    // The success golden replays the committed conversation fixture; the
    // error golden is the deterministic stream-spec refusal, which fires
    // before any input file is opened.
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/captures/pcap/tcp-follow.pcap");
    let success = binary()
        .args(["--output", "json", "follow"])
        .arg(&fixture)
        .args(["--stream", "tcp:0"])
        .output()
        .unwrap();
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let actual: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(actual, json_file("output-follow-success.json"));

    let error = binary()
        .args([
            "--output",
            "json",
            "follow",
            "definitely-missing.pcap",
            "--stream",
            "bogus:0",
        ])
        .output()
        .unwrap();
    assert_eq!(error.status.code(), Some(2));
    let actual: serde_json::Value = serde_json::from_slice(&error.stdout).unwrap();
    assert_eq!(actual, json_file("output-follow-error.json"));
}

#[test]
fn every_command_has_published_success_and_error_goldens() {
    for command_name in CommandName::ALL {
        let command = command_name.as_str();
        let success_name = format!("output-{command}-success.json");
        let event_name = format!("output-{command}-event.json");
        let error_name = format!("output-{command}-error.json");
        let success = example(&success_name);
        let event = example(&event_name);
        assert!(
            success.is_file() || event.is_file(),
            "{command} has no success/event golden"
        );
        if success.is_file() {
            assert_eq!(json_file(&success_name)["command"], command);
        }
        if event.is_file() {
            assert_eq!(json_file(&event_name)["command"], command);
        }
        assert!(
            example(&error_name).is_file(),
            "{command} has no error golden"
        );
        assert_eq!(json_file(&error_name)["command"], command);
    }
}

#[test]
fn packet_document_examples_build_through_the_public_cli() {
    type ResultAssertion = fn(&serde_json::Value);
    for (name, expected_length, assert_result) in [
        ("packet-ipv4-udp.json", 47, None),
        (
            "packet-gre-sctp.json",
            108,
            Some(assert_gre_sctp_example as ResultAssertion),
        ),
        (
            "packet-igmp.json",
            28,
            Some(assert_igmp_example as ResultAssertion),
        ),
        ("packet-raw.yaml", 4, None),
    ] {
        let output = binary()
            .args([
                "--output",
                "json",
                "build",
                "--packet-file",
                example(name).to_str().unwrap(),
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schema"], "packetcraftr.output/v1", "{name}");
        assert_eq!(value["status"], "success", "{name}");
        assert_eq!(value["result"]["length"], expected_length, "{name}");
        if let Some(assert_result) = assert_result {
            assert_result(&value);
        }
    }
}

#[test]
fn published_build_success_output_matches_the_cli() {
    let output = binary()
        .args(["--output", "json", "build", "--packet", "raw(hex=deadbeef)"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, json_file("output-build-success.json"));
}

#[test]
fn published_build_error_output_matches_the_cli() {
    let output = binary()
        .args(["--output", "json", "build", "--packet", "ethernet()/udp()"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, json_file("output-build-error.json"));
}

#[test]
fn published_dissect_success_output_matches_the_cli() {
    let output = binary()
        .args([
            "--output",
            "json",
            "dissect",
            "--hex",
            "deadbeef",
            "--link-type",
            "147",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual, json_file("output-dissect-success.json"));
}

#[test]
fn published_protocol_discovery_outputs_match_the_cli() {
    for (arguments, example_name) in [
        (
            vec!["--output", "json", "protocols"],
            "output-protocols-success.json",
        ),
        (
            vec!["--output", "json", "protocols", "IP4"],
            "output-protocols-detail-success.json",
        ),
        (
            vec!["--output", "json", "protocols", "unknown"],
            "output-protocols-error.json",
        ),
    ] {
        let output = binary().args(arguments).output().unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(actual, json_file(example_name), "{example_name}");
    }
}
