// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{parse_json, run};
#[test]
fn storage_limits_are_checked_before_interface_lookup_or_activation() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("capture.pcapng");
    let name = target.to_str().unwrap();
    for extra in [
        vec!["--rotate-bytes", "0"],
        vec!["--rotate-files", "65", "--rotate-bytes", "1000"],
        vec!["--retention", "ring"],
        vec!["--rotate-interval-ms", "0"],
    ] {
        let mut args = vec![
            "--output",
            "json",
            "capture",
            "--interface",
            "does-not-exist",
            "--write",
            name,
        ];
        args.extend(extra);
        let output = run(&args);
        assert!(!output.status.success());
        assert_eq!(parse_json(&output)["error"]["code"], "cli.capture_files");
        assert!(!target.exists());
    }
    let output = run(&[
        "--output",
        "json",
        "capture",
        "--interface",
        "does-not-exist",
    ]);
    assert!(!output.status.success());
    assert!(
        parse_json(&output)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--write")
    );
    std::fs::write(&target, b"unrelated").unwrap();
    let output = run(&[
        "--output",
        "json",
        "capture",
        "--interface",
        "does-not-exist",
        "--write",
        name,
    ]);
    assert_eq!(parse_json(&output)["error"]["code"], "io.capture_file");
    assert_eq!(std::fs::read(target).unwrap(), b"unrelated");
}

#[test]
fn native_capture_settings_are_checked_before_interface_lookup_or_activation() {
    for extra in [
        vec!["--capture-buffer-bytes", "0"],
        // Smaller than one configured snapshot cannot hold a frame.
        vec!["--capture-buffer-bytes", "1024"],
        // Above the native int range both pcap-family backends take.
        vec!["--capture-buffer-bytes", "99999999999"],
    ] {
        let mut args = vec![
            "--output",
            "text",
            "capture",
            "--interface",
            "does-not-exist",
        ];
        let label = format!("{extra:?}");
        args.extend(extra);
        let output = run(&args);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("cli.capture_setting"), "{label}: {stderr}");
    }
    for extra in [
        vec!["--timestamp-source", "unsynchronized"],
        vec!["--timestamp-precision", "pico"],
    ] {
        let mut args = vec![
            "--output",
            "text",
            "capture",
            "--interface",
            "does-not-exist",
        ];
        let label = format!("{extra:?}");
        args.extend(extra);
        let output = run(&args);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid value"), "{label}: {stderr}");
    }
    // Valid explicit settings proceed past validation to interface resolution,
    // which reports the unknown interface (or an unavailable native capability
    // in portable builds) rather than a setting rejection.
    let output = run(&[
        "--output",
        "text",
        "capture",
        "--interface",
        "does-not-exist",
        "--capture-buffer-bytes",
        "33554432",
        "--timestamp-source",
        "host",
        "--timestamp-precision",
        "nano",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    if cfg!(any(
        feature = "native-route",
        feature = "native-layer2",
        feature = "native-layer3"
    )) {
        assert!(stderr.contains("does-not-exist"), "{stderr}");
    } else {
        assert_eq!(output.status.code(), Some(4), "{stderr}");
        assert!(stderr.contains("capability.unsupported"), "{stderr}");
    }
    assert!(!stderr.contains("cli.capture_setting"), "{stderr}");
}

#[test]
fn decoded_output_options_are_checked_before_interface_lookup() {
    // --dissect/--field only apply to text and NDJSON; the rejection names the
    // accepted formats before any native interface work runs.
    for extra in [
        vec!["--dissect"],
        vec!["--field", "ipv4.destination"],
        vec!["--dissect", "--decode-as", "udp.port=5353:dns"],
    ] {
        for format in ["json", "pcapng"] {
            let mut args = vec![
                "--output",
                format,
                "capture",
                "--interface",
                "does-not-exist",
            ];
            args.extend(extra.clone());
            if format == "json" {
                // JSON capture summaries require --write; decoded output is
                // still rejected first.
                args.extend(["--write", "/dev/null"]);
            }
            let output = run(&args);
            assert!(!output.status.success(), "{args:?} must fail");
            if format == "json" {
                assert_eq!(
                    parse_json(&output)["error"]["code"],
                    "cli.capture_decode_format",
                    "{args:?}"
                );
            } else {
                // Binary formats cannot carry the machine error envelope.
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("cli.capture_decode_format"),
                    "{args:?} stderr"
                );
            }
        }
    }
    // --field and --dissect conflict outright.
    let output = run(&[
        "--output",
        "ndjson",
        "capture",
        "--interface",
        "does-not-exist",
        "--dissect",
        "--field",
        "frame.len",
    ]);
    assert!(!output.status.success());
}

#[test]
fn live_capture_rejects_stream_projection_before_interface_discovery() {
    let output = run(&[
        "--output",
        "ndjson",
        "capture",
        "--interface",
        "does-not-exist",
        "--field",
        "tcp.stream",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("cannot select stream indices"));
}
