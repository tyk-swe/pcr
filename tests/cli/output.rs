// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(unix)]
use std::process::Stdio;

use packetcraftr::capture::{Format as CaptureFormat, LinkType, Reader};

use super::support::{binary, decode_output_hex, temp_path, write_capture, write_link_capture};

#[test]
fn colour_is_terminal_aware_forceable_and_excluded_from_machine_output() {
    let automatic = binary().arg("--help").output().unwrap();
    assert!(automatic.status.success());
    assert!(!automatic.stdout.contains(&0x1b));

    let coloured_help = binary()
        .args(["--color", "always", "--help"])
        .output()
        .unwrap();
    assert!(coloured_help.status.success());
    assert!(coloured_help.stderr.is_empty());
    assert!(coloured_help.stdout.contains(&0x1b));

    let plain_help = binary()
        .args(["--color", "never", "--help"])
        .output()
        .unwrap();
    assert!(plain_help.status.success());
    assert!(!plain_help.stdout.contains(&0x1b));

    let explicit_always_overrides_no_color = binary()
        .env("NO_COLOR", "1")
        .args(["--color", "always", "--help"])
        .output()
        .unwrap();
    assert!(explicit_always_overrides_no_color.status.success());
    assert!(explicit_always_overrides_no_color.stdout.contains(&0x1b));

    let explicit_never_overrides_force = binary()
        .env("CLICOLOR_FORCE", "1")
        .args(["--color", "never", "--help"])
        .output()
        .unwrap();
    assert!(explicit_never_overrides_force.status.success());
    assert!(!explicit_never_overrides_force.stdout.contains(&0x1b));

    let coloured_text = binary()
        .args(["--color", "always", "build", "--packet", "raw(text=hello)"])
        .output()
        .unwrap();
    assert!(coloured_text.status.success());
    assert!(coloured_text.stdout.contains(&0x1b));

    let coloured_error = binary()
        .args(["--color", "always", "build", "--unknown-option"])
        .output()
        .unwrap();
    assert_eq!(coloured_error.status.code(), Some(2));
    assert!(coloured_error.stdout.is_empty());
    assert!(coloured_error.stderr.contains(&0x1b));
    let plain_error =
        anstream::adapter::strip_str(std::str::from_utf8(&coloured_error.stderr).unwrap())
            .to_string();
    assert!(plain_error.contains("\n\nUsage:"));

    let json = binary()
        .args([
            "--color",
            "always",
            "--output",
            "json",
            "build",
            "--packet",
            "raw(text=hello)",
        ])
        .output()
        .unwrap();
    assert!(json.status.success());
    assert!(!json.stdout.contains(&0x1b));
    serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap();

    let json_error = binary()
        .args([
            "--color",
            "always",
            "--output",
            "json",
            "build",
            "--unknown-option",
        ])
        .output()
        .unwrap();
    assert_eq!(json_error.status.code(), Some(2));
    assert!(json_error.stderr.is_empty());
    assert!(!json_error.stdout.contains(&0x1b));
    serde_json::from_slice::<serde_json::Value>(&json_error.stdout).unwrap();

    let ndjson_error = binary()
        .args([
            "--color",
            "always",
            "--output",
            "ndjson",
            "build",
            "--unknown-option",
        ])
        .output()
        .unwrap();
    assert_eq!(ndjson_error.status.code(), Some(2));
    assert!(ndjson_error.stderr.is_empty());
    assert!(!ndjson_error.stdout.contains(&0x1b));
    for line in ndjson_error.stdout.split(|byte| *byte == b'\n') {
        if !line.is_empty() {
            serde_json::from_slice::<serde_json::Value>(line).unwrap();
        }
    }

    let hex = binary()
        .args([
            "--color",
            "always",
            "--output",
            "hex",
            "build",
            "--packet",
            "raw(text=hello)",
        ])
        .output()
        .unwrap();
    assert!(hex.status.success());
    assert!(!hex.stdout.contains(&0x1b));
    assert_eq!(hex.stdout, b"68656c6c6f\n");

    let raw = binary()
        .args([
            "--color",
            "always",
            "--output",
            "raw",
            "build",
            "--packet",
            "raw(hex=001bff)",
        ])
        .output()
        .unwrap();
    assert!(raw.status.success());
    assert!(raw.stderr.is_empty());
    assert_eq!(raw.stdout, [0x00, 0x1b, 0xff]);
}

#[test]
fn exact_bytes_agree_across_json_raw_hex_ndjson_pcap_and_pcapng() {
    let expression = "raw(hex=0001027f80ffdeadbeef)";
    let raw = binary()
        .args(["--output", "raw", "build", "--packet", expression])
        .output()
        .unwrap();
    assert!(raw.status.success());
    let expected = raw.stdout;

    let json = binary()
        .args(["--output", "json", "build", "--packet", expression])
        .output()
        .unwrap();
    assert!(json.status.success());
    let aggregate: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        decode_output_hex(
            aggregate["result"]["bytes_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
        ),
        expected
    );

    let hex = binary()
        .args(["--output", "hex", "build", "--packet", expression])
        .output()
        .unwrap();
    assert!(hex.status.success());
    assert_eq!(decode_output_hex(&hex.stdout), expected);

    let path = write_link_capture(LinkType::RAW, &[&expected]);
    let read_hex = binary()
        .args(["--output", "hex", "read"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(read_hex.status.success());
    assert_eq!(decode_output_hex(&read_hex.stdout), expected);

    let ndjson = binary()
        .args(["--output", "ndjson", "read"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(ndjson.status.success());
    let record: serde_json::Value = serde_json::from_slice(&ndjson.stdout).unwrap();
    assert_eq!(
        decode_output_hex(
            record["result"]["frame"]["bytes_hex"]
                .as_str()
                .unwrap()
                .as_bytes()
        ),
        expected
    );
    assert_eq!(
        record["result"]["frame"]["captured_length"],
        expected.len() as u64
    );
    assert_eq!(
        record["result"]["frame"]["original_length"],
        expected.len() as u64
    );

    for format in ["pcap", "pcapng"] {
        let output = binary()
            .args(["--output", format, "read"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut reader = Reader::new(std::io::Cursor::new(output.stdout)).unwrap();
        let frame = reader.next_frame().unwrap().unwrap();
        assert_eq!(frame.bytes().as_ref(), expected, "{format}");
        assert_eq!(frame.captured_length() as usize, expected.len(), "{format}");
        assert_eq!(frame.original_length() as usize, expected.len(), "{format}");
        assert!(reader.next_frame().unwrap().is_none(), "{format}");
    }
    std::fs::remove_file(path).unwrap();
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
fn fuzz_text_escapes_control_values_while_json_keeps_them_structured() {
    let common = [
        "fuzz",
        "--packet",
        "bsd_null(family=2,byte_order=\"little\")/ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=1,dport=2)",
        "--seed",
        "0",
        "--cases",
        "1",
        "--strategy",
        "boundary",
        "--field",
        "0.byte_order",
    ];
    let text = binary().args(common).output().unwrap();
    assert!(text.status.success());
    assert!(!text.stdout.contains(&0x1b));
    assert!(String::from_utf8(text.stdout).unwrap().contains("\\u001b"));

    let json = binary()
        .args(["--output", "json"])
        .args(common)
        .output()
        .unwrap();
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        value["result"]["cases"][0]["mutation"]["value"]["value"],
        "\u{1b}[31mcontrol\u{1b}[0m"
    );
}

#[test]
fn read_exposes_bounded_capture_file_writers() {
    let path = write_capture(&[b"one", b"two"], false);
    let output = binary()
        .args([
            "--output",
            "pcapng",
            "read",
            path.to_str().unwrap(),
            "--max-frames",
            "2",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut reader = Reader::new(std::io::Cursor::new(output.stdout)).unwrap();
    assert_eq!(reader.format(), CaptureFormat::PcapNg);
    assert_eq!(
        reader.next_frame().unwrap().unwrap().bytes().as_ref(),
        b"one"
    );
    assert_eq!(
        reader.next_frame().unwrap().unwrap().bytes().as_ref(),
        b"two"
    );
    assert!(reader.next_frame().unwrap().is_none());
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
fn malformed_read_preserves_completed_binary_output_before_terminal_error() {
    let path = write_capture(&[b"ok"], true);

    let hex = binary()
        .args(["--output", "hex", "read"])
        .arg(&path)
        .output()
        .unwrap();
    let binary_outputs = ["pcap", "pcapng"].map(|format| {
        let output = binary()
            .args(["--output", format, "read"])
            .arg(&path)
            .output()
            .unwrap();
        (format, output)
    });
    std::fs::remove_file(path).unwrap();

    assert_eq!(hex.status.code(), Some(3));
    assert_eq!(hex.stdout, b"6f6b\n");
    assert!(String::from_utf8_lossy(&hex.stderr).contains("truncated"));

    for (format, output) in binary_outputs {
        assert_eq!(output.status.code(), Some(3), "{format}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("truncated"),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut reader = Reader::new(std::io::Cursor::new(output.stdout)).unwrap();
        assert_eq!(
            reader.next_frame().unwrap().unwrap().bytes().as_ref(),
            b"ok",
            "{format}"
        );
        assert!(reader.next_frame().unwrap().is_none(), "{format}");
    }
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
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("text, ndjson, hex")
    );
}

#[cfg(unix)]
#[test]
fn closed_stdout_is_cleanly_classified_for_every_output_family() {
    let bytes = vec![0u8; 1024 * 1024];
    let raw_path = temp_path("closed-stdout-raw");
    std::fs::write(&raw_path, &bytes).unwrap();
    let capture_path = write_link_capture(LinkType(147), &[&bytes]);

    for format in ["json", "hex", "raw"] {
        let mut child = binary()
            .args(["--output", format, "dissect", "--file"])
            .arg(&raw_path)
            .args(["--link-type", "147"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(5), "{format}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("write stdout failed"), "{format}: {stderr}");
        assert!(!stderr.contains("panicked"), "{format}: {stderr}");
    }

    for format in ["text", "ndjson", "pcap", "pcapng"] {
        let mut child = binary()
            .args(["--output", format, "read"])
            .arg(&capture_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(5), "{format}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("write stdout failed")
                || stderr.contains("write capture output failed")
                || stderr.contains("capture I/O failed"),
            "{format}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{format}: {stderr}");
    }

    std::fs::remove_file(raw_path).unwrap();
    std::fs::remove_file(capture_path).unwrap();
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
