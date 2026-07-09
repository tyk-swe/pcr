// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
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
    assert_eq!(value["error"]["kind"], "capability");
    assert_eq!(value["command"], "send");
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

#[cfg(unix)]
#[test]
fn closed_stdout_is_a_runtime_io_error_without_a_panic() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "packetcraftr-closed-stdout-{}-{suffix}.bin",
        std::process::id()
    ));
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
