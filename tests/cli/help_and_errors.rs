// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::process::Stdio;

use super::support::{binary, normalize_cli_text};

#[test]
fn cli_help_parse_error_and_version_match_the_committed_goldens() {
    const COMMANDS: &[&str] = &[
        "build",
        "dissect",
        "read",
        "interfaces",
        "plan",
        "send",
        "exchange",
        "capture",
        "replay",
        "scan",
        "traceroute",
        "dns",
        "fuzz",
        "routes",
    ];

    let mut sections = Vec::with_capacity(COMMANDS.len() + 1);
    for (label, arguments) in std::iter::once(("packetcraftr --help".to_owned(), vec!["--help"]))
        .chain(COMMANDS.iter().map(|command| {
            (
                format!("packetcraftr {command} --help"),
                vec![*command, "--help"],
            )
        }))
    {
        let output = binary().args(arguments).output().unwrap();
        assert!(output.status.success(), "{label}");
        assert!(output.stderr.is_empty(), "{label}");
        sections.push(format!(
            "===== {label} =====\n{}\n",
            normalize_cli_text(&output.stdout).trim_end()
        ));
    }
    assert_eq!(
        sections.join("\n"),
        normalize_cli_text(include_str!("../golden/cli-help.txt").as_bytes())
    );

    let parse_error = binary()
        .args(["build", "--unknown-option"])
        .output()
        .unwrap();
    assert_eq!(parse_error.status.code(), Some(2));
    assert!(parse_error.stdout.is_empty());
    assert_eq!(
        normalize_cli_text(&parse_error.stderr),
        normalize_cli_text(include_str!("../golden/cli-parse-error.txt").as_bytes())
    );

    let version = binary().arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(version.stderr.is_empty());
    assert_eq!(
        normalize_cli_text(&version.stdout),
        normalize_cli_text(include_str!("../golden/cli-version.txt").as_bytes())
    );
}

#[test]
fn bare_invocation_prints_readable_help_to_stderr() {
    let output = binary().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.contains(&0x1b));

    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(stderr.contains("Reflective packet construction"));
    assert!(stderr.contains("\n\nUsage: packetcraftr [OPTIONS] <COMMAND>\n\n"));
    assert!(stderr.contains("\nCommands:\n"));
    assert!(!stderr.contains("\\n"));
}

#[test]
fn parse_error_output_detection_respects_the_end_of_options_marker() {
    let positional = binary()
        .args(["read", "--", "--output=json", "extra"])
        .output()
        .unwrap();
    assert_eq!(positional.status.code(), Some(2));
    assert!(positional.stdout.is_empty());
    assert!(!positional.stderr.is_empty());
    assert!(serde_json::from_slice::<serde_json::Value>(&positional.stderr).is_err());

    let option = binary()
        .args(["--output=json", "read", "--unknown-option"])
        .output()
        .unwrap();
    assert_eq!(option.status.code(), Some(2));
    assert!(option.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&option.stdout).unwrap();
    assert_eq!(value["error"]["kind"], "cli");

    let command_shaped_positional = binary()
        .args(["--output=json", "--", "scan"])
        .output()
        .unwrap();
    assert_eq!(command_shaped_positional.status.code(), Some(2));
    assert!(command_shaped_positional.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&command_shaped_positional.stdout).unwrap();
    assert!(value["command"].is_null());
    assert_eq!(value["error"]["kind"], "cli");
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

#[test]
fn conflicting_recipe_sources_use_cli_exit_code() {
    let output = binary()
        .args(["build", "--packet", "raw()", "--packet-file", "packet.json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn overflowing_numeric_interface_selectors_are_cli_errors_before_platform_io() {
    for arguments in [
        vec![
            "--output",
            "json",
            "plan",
            "--packet",
            "raw()",
            "--interface",
            "4294967296",
        ],
        vec![
            "--output",
            "json",
            "replay",
            "definitely-missing.pcap",
            "--interface",
            "4294967296",
        ],
    ] {
        let output = binary().args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["error"]["kind"], "cli");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("interface index")
        );
    }
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
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("exactly one")
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_arguments_do_not_panic_the_structured_parse_error_path() {
    use std::os::unix::ffi::OsStringExt;

    let invalid = std::ffi::OsString::from_vec(b"bad\xff".to_vec());
    let output = binary()
        .args(["--output", "json", "build", "--unknown-option"])
        .arg(invalid)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "build");
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["kind"], "cli");
}
