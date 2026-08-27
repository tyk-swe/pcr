// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

mod support;
use support::{parse_json, run, run_success};

const V1_IPV4_UDP: &str = r#"{
  "schema": "packetcraftr.packet/v1",
  "layers": [
    {
      "protocol": "ethernet",
      "fields": {
        "destination": { "type": "mac", "value": [2, 0, 0, 0, 0, 2] },
        "source": { "type": "mac", "value": [2, 0, 0, 0, 0, 1] }
      }
    },
    {
      "protocol": "ipv4",
      "fields": {
        "identification": { "type": "unsigned", "value": 4660 },
        "dont_fragment": { "type": "bool", "value": true },
        "ttl": { "type": "unsigned", "value": 64 },
        "source": { "type": "ipv4", "value": "192.0.2.1" },
        "destination": { "type": "ipv4", "value": "192.0.2.2" }
      }
    },
    {
      "protocol": "udp",
      "fields": {
        "source_port": { "type": "unsigned", "value": 49152 },
        "destination_port": { "type": "unsigned", "value": 9 }
      }
    },
    {
      "protocol": "raw",
      "fields": {
        "bytes": { "type": "bytes", "value": [104, 101, 108, 108, 111] }
      }
    }
  ]
}"#;

const V1_GRE_SCTP: &str = r#"{
  "schema": "packetcraftr.packet/v1",
  "layers": [
    {
      "protocol": "ipv4",
      "fields": {
        "source": { "type": "ipv4", "value": "192.0.2.1" },
        "destination": { "type": "ipv4", "value": "192.0.2.2" }
      }
    },
    {
      "protocol": "gre",
      "fields": {
        "key": { "type": "unsigned", "value": 287454020 },
        "sequence": { "type": "unsigned", "value": 7 }
      }
    },
    {
      "protocol": "ipv6",
      "fields": {
        "source": { "type": "ipv6", "value": "2001:db8::1" },
        "destination": { "type": "ipv6", "value": "2001:db8::2" }
      }
    },
    {
      "protocol": "sctp",
      "fields": {
        "source_port": { "type": "unsigned", "value": 40000 },
        "destination_port": { "type": "unsigned", "value": 5000 },
        "verification_tag": { "type": "unsigned", "value": 0 }
      }
    },
    {
      "protocol": "raw",
      "fields": {
        "bytes": {
          "type": "bytes",
          "value": [
            1, 0, 0, 20, 17, 34, 51, 68, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0
          ]
        }
      }
    }
  ]
}"#;

const V1_IGMP: &str = r#"{
  "schema": "packetcraftr.packet/v1",
  "layers": [
    {
      "protocol": "ipv4",
      "fields": {
        "source": { "type": "ipv4", "value": "192.0.2.1" },
        "destination": { "type": "ipv4", "value": "224.0.0.1" },
        "ttl": { "type": "unsigned", "value": 1 }
      }
    },
    {
      "protocol": "igmp",
      "fields": {
        "type": { "type": "unsigned", "value": 17 },
        "code": { "type": "unsigned", "value": 0 },
        "body": { "type": "bytes", "value": [224, 0, 0, 1] }
      }
    }
  ]
}"#;

const V1_RAW: &str = r#"schema: packetcraftr.packet/v1
layers:
  - protocol: raw
    fields:
      bytes:
        value: [222, 173, 190, 239]
        type: bytes
"#;

#[test]
fn convert_rewrites_v1_and_builds_identical_raw_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let test_cases = [
        ("packet-ipv4-udp.json", V1_IPV4_UDP),
        ("packet-gre-sctp.json", V1_GRE_SCTP),
        ("packet-igmp.json", V1_IGMP),
        ("packet-raw.yaml", V1_RAW),
    ];

    for (name, v1_content) in test_cases {
        let v1_path = dir.path().join(format!("v1_{name}"));
        fs::write(&v1_path, v1_content).expect("write v1");

        let to_convert_path = dir.path().join(name);
        fs::write(&to_convert_path, v1_content).expect("write to_convert");

        // Build raw bytes from original v1
        let v1_build = run_success(&[
            "--output",
            "raw",
            "build",
            "--packet-file",
            v1_path.to_str().unwrap(),
        ]);

        // Convert the to_convert_path
        let convert_out = run_success(&["convert", to_convert_path.to_str().unwrap()]);
        let stdout = String::from_utf8_lossy(&convert_out.stdout);
        assert!(stdout.contains(&format!("converted {}", to_convert_path.display())));

        // Build raw bytes from converted file
        let v2_build = run_success(&[
            "--output",
            "raw",
            "build",
            "--packet-file",
            to_convert_path.to_str().unwrap(),
        ]);

        assert_eq!(
            v1_build.stdout, v2_build.stdout,
            "raw bytes built from v1 and converted v2 document must match for {name}"
        );
    }
}

#[test]
fn check_on_published_examples_exits_zero() {
    let docs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/documents");
    let output = run_success(&["convert", "--check", docs.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("already v2"));
    assert!(stdout.contains("converted 0"));
}

#[test]
fn check_on_temp_v1_file_exits_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let v1_path = dir.path().join("test-v1.json");
    fs::write(&v1_path, V1_IPV4_UDP).expect("write v1");

    let output = run(&["convert", "--check", v1_path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("would convert {}", v1_path.display())));
    assert!(stdout.contains("converted 1, already v2 0, failed 0"));
}

#[test]
fn v2_file_conversion_is_a_noop_with_mtime_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let v2_path = dir.path().join("packet.json");
    let v2_content = r#"{
  "schema": "packetcraftr.packet/v2",
  "layers": [
    {
      "raw": {
        "bytes": "0xdeadbeef"
      }
    }
  ]
}"#;
    fs::write(&v2_path, v2_content).expect("write v2");

    let initial_mtime = fs::metadata(&v2_path)
        .expect("metadata")
        .modified()
        .expect("mtime");

    // Small delay to ensure any touch would change mtime
    std::thread::sleep(std::time::Duration::from_millis(50));

    let output = run_success(&["convert", v2_path.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("already v2 {}", v2_path.display())));
    assert!(stdout.contains("converted 0, already v2 1, failed 0"));

    let final_mtime = fs::metadata(&v2_path)
        .expect("metadata")
        .modified()
        .expect("mtime");
    assert_eq!(
        initial_mtime, final_mtime,
        "mtime must be unchanged for v2 document"
    );
}

#[test]
fn directory_input_recurses_subdirectories() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sub = dir.path().join("subdir");
    fs::create_dir(&sub).expect("create subdir");

    let file1 = dir.path().join("file1.json");
    let file2 = sub.join("file2.yaml");
    fs::write(&file1, V1_IPV4_UDP).expect("write file1");
    fs::write(&file2, V1_RAW).expect("write file2");

    let output = run_success(&["convert", dir.path().to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&format!("converted {}", file1.display())));
    assert!(stdout.contains(&format!("converted {}", file2.display())));
    assert!(stdout.contains("converted 2, already v2 0, failed 0"));
}

#[test]
fn build_v1_packet_file_emits_deprecation_warning_with_convert_command() {
    let dir = tempfile::tempdir().expect("tempdir");
    let v1_path = dir.path().join("my-packet.json");
    fs::write(&v1_path, V1_IPV4_UDP).expect("write v1");

    let output = run_success(&[
        "--output",
        "text",
        "build",
        "--packet-file",
        v1_path.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("document.deprecated_schema"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains(&format!("run `packetcraftr convert {}`", v1_path.display())),
        "stdout: {stdout}"
    );

    // Also test with JSON output
    let json_out = run_success(&[
        "--output",
        "json",
        "build",
        "--packet-file",
        v1_path.to_str().unwrap(),
    ]);
    let value = parse_json(&json_out);
    let diagnostics = value["diagnostics"].as_array().expect("diagnostics array");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0]["code"], "document.deprecated_schema");
    assert_eq!(diagnostics[0]["severity"], "warning");
    assert!(
        diagnostics[0]["message"]
            .as_str()
            .unwrap()
            .contains(&format!("run `packetcraftr convert {}`", v1_path.display()))
    );
}

#[test]
fn convert_stdout_flag_outputs_converted_document_to_stdout() {
    let dir = tempfile::tempdir().expect("tempdir");
    let v1_path = dir.path().join("packet.json");
    fs::write(&v1_path, V1_IPV4_UDP).expect("write v1");

    let output = run_success(&["convert", "--stdout", v1_path.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""schema": "packetcraftr.packet/v2""#));
    assert!(stdout.contains(r#""ethernet""#));

    // File itself should still be v1
    let disk_content = fs::read_to_string(&v1_path).expect("read");
    assert!(disk_content.contains(r#""schema": "packetcraftr.packet/v1""#));
}

#[test]
fn convert_stdout_with_json_format_emits_only_the_json_envelope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let v1_path = dir.path().join("packet.json");
    fs::write(&v1_path, V1_IPV4_UDP).expect("write v1");

    let output = run_success(&[
        "--output",
        "json",
        "convert",
        "--stdout",
        v1_path.to_str().unwrap(),
    ]);
    // If the raw converted document text leaked onto stdout ahead of the
    // envelope, this would fail to parse as one JSON value.
    let value = parse_json(&output);
    assert_eq!(
        value["result"]["converted"][0],
        v1_path.to_str().unwrap()
    );
}

#[test]
fn convert_stdin_with_json_format_emits_only_the_json_envelope() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(["--output", "json", "convert", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI process must start");
    child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(V1_IPV4_UDP.as_bytes())
        .expect("write stdin");
    let output = child.wait_with_output().expect("process must finish");
    assert!(
        output.status.success(),
        "convert - failed: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let value = parse_json(&output);
    assert_eq!(value["result"]["converted"][0], "-");
}
