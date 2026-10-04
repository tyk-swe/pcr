// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{parse_json, run, run_success};

#[test]
fn http_rejects_zero_ports_and_out_of_range_body_limits_as_usage_errors() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    for (flag, value) in [
        ("--http-port", "0"),
        ("--max-http-body-bytes", "0"),
        ("--max-http-body-bytes", "268435457"),
    ] {
        let output = run(&["--output", "json", "http", path, flag, value]);
        assert_eq!(output.status.code(), Some(2), "{flag} {value}: {output:?}");
        let error = parse_json(&output)["error"].clone();
        assert_eq!(error["kind"], "usage", "{flag} {value}");
        assert!(
            error["message"].as_str().unwrap().contains(flag),
            "{flag} {value}: {error}"
        );
    }
    let accepted = parse_json(&run_success(&[
        "--output",
        "json",
        "http",
        path,
        "--max-http-body-bytes",
        "268435456",
        "--http-port",
        "65535",
    ]));
    assert_eq!(accepted["result"]["messages"].as_array().unwrap().len(), 2);
}

#[test]
fn zero_application_message_limit_is_a_usage_error() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let path = path.to_str().unwrap();
    let output = run(&[
        "--output",
        "json",
        "http",
        path,
        "--max-application-messages",
        "0",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let error = &parse_json(&output)["error"];
    assert_eq!(error["code"], "cli.analysis_limit");
    assert_eq!(error["kind"], "usage");
    assert!(
        error["message"].as_str().unwrap().contains("max_messages"),
        "{error}"
    );
}
