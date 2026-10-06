// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use crate::process_support::run_with_stdin;
use common::{parse_json, path_text, run};

#[test]
fn udp_payload_file_and_stdin_parity_includes_empty_input() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload.bin");
    for input in [b"".as_slice(), b"hello\x00\xff".as_slice()] {
        std::fs::write(&payload, input).unwrap();
        // Deny one byte below the probe cost so neither source transmits.
        let max_bytes = (59 + input.len()).to_string();
        let mut arguments = vec![
            "--output",
            "json",
            "scan",
            "127.0.0.1",
            "--transport",
            "udp",
            "--ports",
            "50001",
            "--max-bytes",
            &max_bytes,
            "--udp-payload-file",
            path_text(&payload),
        ];
        let file = run(&arguments);
        *arguments.last_mut().unwrap() = "-";
        let stdin = run_with_stdin(&arguments, input);
        assert_eq!(file.status.code(), Some(6));
        assert_eq!(parse_json(&file)["error"]["code"], "policy.byte_limit");
        assert_eq!(stdin.status.code(), file.status.code());
        assert_eq!(parse_json(&stdin), parse_json(&file));
        assert_eq!(stdin.stderr, file.stderr);
    }
}

#[test]
fn udp_payload_charged_before_probe_execution() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload.bin");
    std::fs::write(&payload, b"hello\x00\xff").unwrap();
    for options in [
        vec!["--udp-payload-hex", "68:65:6c:6c:6f:00:ff"],
        vec!["--udp-payload-file", path_text(&payload)],
    ] {
        // One IPv4 probe is charged 60 bytes plus the payload, so this scan
        // costs 67. A limit of 66 denies only when the payload is charged.
        let mut arguments = vec![
            "--output",
            "json",
            "scan",
            "127.0.0.1",
            "--transport",
            "udp",
            "--ports",
            "50001",
            "--max-bytes",
            "66",
        ];
        arguments.extend(options);
        let output = run(&arguments);
        assert!(!output.status.success());
        assert_eq!(parse_json(&output)["error"]["code"], "policy.byte_limit");
    }
}

#[test]
fn oversize_udp_error_naming_payload() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload.bin");
    std::fs::write(
        &payload,
        vec![0; packetcraftr::scan::MAX_UDP_PAYLOAD_BYTES + 1],
    )
    .unwrap();
    let output = run(&[
        "--output",
        "json",
        "scan",
        "127.0.0.1",
        "--transport",
        "udp",
        "--ports",
        "50001",
        "--udp-payload-file",
        path_text(&payload),
    ]);
    assert_eq!(output.status.code(), Some(2));
    let value = parse_json(&output);
    assert_eq!(value["error"]["code"], "cli.error");
    let message = value["error"]["message"].as_str().unwrap();
    assert!(message.contains("UDP payload"), "{message}");
    assert!(message.contains("65507"), "{message}");
}
