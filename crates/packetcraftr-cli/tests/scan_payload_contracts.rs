// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{parse_json, path_text, run};

#[test]
fn udp_payload_input_is_charged_before_probe_execution() {
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
fn oversized_udp_payload_file_is_a_usage_error_naming_the_payload() {
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

#[test]
fn invalid_udp_payload_options_are_usage_errors_naming_the_cause() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload.bin");
    std::fs::write(&payload, b"hello\x00\xff").unwrap();
    for (options, expected) in [
        (
            vec!["--transport", "tcp", "--udp-payload-hex", ""],
            "require --transport udp",
        ),
        (
            vec![
                "--transport",
                "icmp",
                "--udp-payload-file",
                path_text(&payload),
            ],
            "require --transport udp",
        ),
        (
            vec!["--transport", "udp", "--udp-payload-hex", "zz"],
            "invalid hex at byte 0",
        ),
        (
            vec!["--transport", "udp", "--udp-payload-hex", "abc"],
            "even number of digits",
        ),
        (
            vec![
                "--transport",
                "udp",
                "--udp-payload-hex",
                "00",
                "--udp-payload-file",
                path_text(&payload),
            ],
            "cannot be used with",
        ),
    ] {
        let mut arguments = vec!["--output", "json", "scan", "127.0.0.1", "--ports", "50001"];
        arguments.extend(options);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let message = parse_json(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(message.contains(expected), "{arguments:?}: {message}");
    }
}
