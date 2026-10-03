// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, Output};

fn build_payload(spec: &OsStr, format: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            format,
            "build",
            "--packet",
            "raw()",
            "--payload-file",
        ])
        .arg(spec)
        .output()
        .expect("offline CLI must finish")
}

fn payload_spec(selector: &str, path: &Path) -> OsString {
    let mut spec = OsString::from(selector);
    spec.push("=");
    spec.push(path);
    spec
}

#[test]
fn payload_file_preserves_unicode_spaces_and_equals_in_paths() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("界 café = bytes.bin");
    let expected = b"payload\x00\xff";
    std::fs::write(&payload, expected).unwrap();
    for selector in ["raw.bytes", "0.bytes"] {
        let output = build_payload(&payload_spec(selector, &payload), "raw");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, expected);
        assert!(output.stderr.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn payload_file_preserves_non_utf8_paths_without_opening_the_lossy_alternative() {
    use std::os::unix::ffi::OsStrExt;

    let directory = tempfile::tempdir().unwrap();
    let name = OsStr::from_bytes(b"payload-\xff=bytes.bin");
    let payload = directory.path().join(name);
    let expected = b"exact filename\x00\xff";
    std::fs::write(&payload, expected).unwrap();
    std::fs::write(
        directory.path().join(name.to_string_lossy().as_ref()),
        b"wrong file",
    )
    .unwrap();
    for selector in ["raw.bytes", "0.bytes"] {
        let output = build_payload(&payload_spec(selector, &payload), "raw");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, expected);
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn payload_file_keeps_selector_errors_separate_from_path_io_errors() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing = payload.bin");
    for spec in [
        OsString::from("raw.bytes"),
        payload_spec("raw.no_such_field", &missing),
    ] {
        let output = build_payload(&spec, "json");
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            report["error"]["message"]
                .as_str()
                .unwrap()
                .contains("--payload-file")
        );
        assert!(
            !report["error"]["message"]
                .as_str()
                .unwrap()
                .contains("open ")
        );
    }
    let output = build_payload(&payload_spec("raw.bytes", &missing), "json");
    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["error"]["code"], "io.runtime");
    assert!(
        report["error"]["message"]
            .as_str()
            .unwrap()
            .contains("missing = payload.bin")
    );
}

#[cfg(unix)]
#[test]
fn payload_file_rejects_non_utf8_selectors_before_opening_the_path() {
    use std::os::unix::ffi::OsStrExt;

    let output = build_payload(OsStr::from_bytes(b"raw.\xff=missing.bin"), "json");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--payload-file requires")
    );
}
