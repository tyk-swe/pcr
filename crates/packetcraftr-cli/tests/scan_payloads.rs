// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use support::{parse_json, path_text, run};

#[test]
fn udp_payload_input_is_bounded_and_charged_before_probe_execution() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("payload.bin");
    std::fs::write(&payload, b"hello\x00\xff").unwrap();
    for options in [
        vec!["--udp-payload-hex", "68:65:6c:6c:6f:00:ff"],
        vec!["--udp-payload-file", path_text(&payload)],
    ] {
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
            "54",
        ];
        arguments.extend(options);
        let output = run(&arguments);
        assert!(!output.status.success());
        assert_eq!(parse_json(&output)["error"]["code"], "policy.byte_limit");
    }
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
    assert!(!output.status.success());
    assert!(
        parse_json(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("65507")
    );
    for options in [
        vec!["--transport", "tcp", "--udp-payload-hex", ""],
        vec![
            "--transport",
            "icmp",
            "--udp-payload-file",
            path_text(&payload),
        ],
        vec!["--transport", "udp", "--udp-payload-hex", "zz"],
        vec!["--transport", "udp", "--udp-payload-hex", "abc"],
        vec![
            "--transport",
            "udp",
            "--udp-payload-hex",
            "00",
            "--udp-payload-file",
            path_text(&payload),
        ],
    ] {
        let mut arguments = vec!["--output", "json", "scan", "127.0.0.1"];
        arguments.extend(options);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2));
        parse_json(&output);
    }
}
