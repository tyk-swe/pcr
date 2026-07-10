// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
}

fn temp_path(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "packetcraftr-{label}-{}-{suffix}.bin",
        std::process::id()
    ))
}

fn write_capture(frames: &[&[u8]], malformed_tail: bool) -> PathBuf {
    let mut writer =
        packetcraftr::CaptureWriter::pcap(Vec::new(), packetcraftr::LinkType::ETHERNET).unwrap();
    for (index, bytes) in frames.iter().enumerate() {
        let frame = packetcraftr::CapturedFrame::new(
            UNIX_EPOCH + std::time::Duration::from_secs(index as u64),
            packetcraftr::LinkType::ETHERNET,
            bytes.to_vec(),
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    let mut bytes = writer.into_inner();
    if malformed_tail {
        bytes.extend_from_slice(&[0_u8; 8]);
    }
    let path = temp_path("typed-output");
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn build_expression_emits_complete_frame_hex() {
    let output = binary()
        .args([
            "--output",
            "hex",
            "build",
            "--packet",
            "ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=12345,dport=9)/raw(text=hi)",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hex = String::from_utf8(output.stdout).unwrap();
    assert!(hex.trim().starts_with("45"));
    assert!(hex.trim().ends_with("6869"));
}

#[test]
fn json_build_uses_versioned_success_envelope() {
    let output = binary()
        .args(["--output", "json", "build", "--packet", "raw(hex=deadbeef)"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["command"], "build");
    assert_eq!(value["mode"], "aggregate");
    assert_eq!(value["status"], "success");
    assert_eq!(value["result"]["bytes_hex"], "deadbeef");
    assert!(value["diagnostics"].is_array());
}

#[test]
fn unavailable_live_command_uses_capability_exit_code_and_json_error() {
    let output = binary()
        .args(["--output", "json", "send"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["mode"], "aggregate");
    assert_eq!(value["error"]["kind"], "capability");
    assert_eq!(value["command"], "send");
}

#[test]
fn capture_commands_reserve_the_documented_queue_limit_contract() {
    for command in ["capture", "exchange"] {
        let output = binary().args([command, "--help"]).output().unwrap();
        assert!(output.status.success(), "{command}");
        let help = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "--max-queue-frames",
            "--max-captured-bytes",
            "--snap-length",
            "--overflow-policy",
            "drop-newest",
            "drop-oldest",
            "[default: 4096]",
        ] {
            assert!(
                help.contains(expected),
                "{command}: missing {expected}\n{help}"
            );
        }
    }
}

#[cfg(all(windows, feature = "live", not(feature = "native-route")))]
#[test]
fn portable_windows_interfaces_reports_the_native_capability_boundary() {
    let output = binary()
        .args(["--output", "json", "interfaces"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["kind"], "capability");
    assert_eq!(value["command"], "interfaces");
    let message = value["error"]["message"].as_str().unwrap();
    assert!(message.contains("portable profile"));
    assert!(message.contains("Windows native adapter"));
    assert!(message.contains("Npcap"));
}

#[cfg(all(windows, feature = "native-route"))]
#[test]
fn native_windows_interfaces_uses_ip_helper() {
    let output = binary()
        .args(["--output", "json", "interfaces"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "success");
    assert_eq!(value["command"], "interfaces");
    let interfaces = value["result"]["interfaces"].as_array().unwrap();
    assert!(!interfaces.is_empty());
    assert!(interfaces.iter().all(|interface| {
        interface["index"].as_u64().is_some_and(|index| index != 0)
            && interface["mtu"].as_u64().is_some_and(|mtu| mtu != 0)
    }));
}

#[test]
fn conflicting_recipe_sources_use_cli_exit_code() {
    let output = binary()
        .args(["build", "--packet", "raw()", "--packet-file", "packet.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn piped_stdin_cannot_be_silently_ignored_by_an_explicit_recipe() {
    let mut child = binary()
        .args(["--output", "json", "build", "--packet", "raw(hex=00)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"raw(hex=ff)")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert!(value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("exactly one"));
}

#[test]
fn cli_parse_errors_requested_as_ndjson_are_sequence_zero_records() {
    let output = binary()
        .args(["--output", "ndjson", "build", "--unknown-option"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "build");
    assert_eq!(value["mode"], "stream");
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["kind"], "cli");
}

#[test]
fn read_ndjson_success_records_have_frozen_sequences() {
    let path = write_capture(&[&[0, 1], &[2, 3, 4]], false);
    let output = binary()
        .args(["--output", "ndjson", "read"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    for (sequence, record) in records.iter().enumerate() {
        assert_eq!(record["command"], "read");
        assert_eq!(record["mode"], "stream");
        assert_eq!(record["sequence"], sequence as u64);
        assert_eq!(record["status"], "success");
    }
    assert_eq!(records[0]["result"]["frame"]["bytes_hex"], "0001");
    assert_eq!(records[1]["result"]["frame"]["bytes_hex"], "020304");
}

#[test]
fn read_ndjson_terminal_errors_use_the_next_unused_sequence() {
    let path = write_capture(&[&[0xaa]], true);
    let output = binary()
        .args(["--output", "ndjson", "read"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();

    assert_eq!(output.status.code(), Some(3));
    let records = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["status"], "success");
    assert_eq!(records[0]["sequence"], 0);
    assert_eq!(records[1]["status"], "error");
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["error"]["kind"], "packet");
}

#[test]
fn unsupported_json_for_read_is_typed_before_opening_the_input() {
    let output = binary()
        .args(["--output", "json", "read", "definitely-missing.pcap"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["mode"], "aggregate");
    assert_eq!(value["error"]["code"], "cli.output_format");
    assert!(value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("text, ndjson, hex"));
}

#[cfg(unix)]
#[test]
fn closed_stdout_is_a_runtime_io_error_without_a_panic() {
    let path = temp_path("closed-stdout");
    std::fs::write(&path, vec![0u8; 1024 * 1024]).unwrap();

    let mut child = binary()
        .args(["--output", "hex", "dissect", "--file"])
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    std::fs::remove_file(path).unwrap();

    assert_eq!(output.status.code(), Some(5));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("write stdout failed"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn text_errors_escape_terminal_controls_while_json_stays_structured() {
    let path = "missing-\u{1b}[31m-\n-packet.bin";
    let text = binary().args(["dissect", "--file", path]).output().unwrap();
    assert_eq!(text.status.code(), Some(2));
    assert!(!text.stderr.contains(&0x1b));
    let rendered = String::from_utf8(text.stderr).unwrap();
    assert!(rendered.contains("\\u{1b}"), "{rendered:?}");
    assert!(rendered.contains("\\n"), "{rendered:?}");

    let machine = binary()
        .args(["--output", "json", "dissect", "--file", path])
        .output()
        .unwrap();
    assert_eq!(machine.status.code(), Some(2));
    assert!(!machine.stdout.contains(&0x1b));
    let value: serde_json::Value = serde_json::from_slice(&machine.stdout).unwrap();
    let message = value["error"]["message"].as_str().unwrap();
    assert!(message.contains('\u{1b}'));
    assert!(message.contains('\n'));
    assert_eq!(value["error"]["kind"], "cli");
}
