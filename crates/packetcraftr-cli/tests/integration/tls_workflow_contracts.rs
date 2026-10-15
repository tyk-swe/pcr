// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::common;

use common::{path_text, run};

#[test]
fn limit_fails_reported_before_capture_read() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("does-not-exist.pcapng");
    let output = run(&["tls", path_text(&missing), "--max-tls-sessions", "0"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("non-zero"),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    for value in ["0", "1024"] {
        let floored = run(&["tls", path_text(&missing), "--max-tls-buffer-bytes", value]);
        assert_eq!(floored.status.code(), Some(2), "{value}");
        let rendered = String::from_utf8_lossy(&floored.stderr);
        assert!(
            rendered.contains(&format!("--max-tls-buffer-bytes={value}")),
            "{rendered}"
        );
        assert!(
            rendered.contains(&packetcraftr_core::analysis::tls::MAX_DIRECTION_BUFFER.to_string()),
            "{rendered}"
        );
        assert!(
            !rendered.contains("max_direction_bytes"),
            "the internal field name never reaches the user: {rendered}"
        );
    }
}

#[test]
fn server_sessions_report_the_published_ja4s_fingerprint() {
    let capture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/tls-handshake.pcapng");
    let report = common::parse_json(&common::run_success(&[
        "--output",
        "json",
        "analyze",
        "tls",
        path_text(&capture),
    ]));
    let sessions = report["result"]["sessions"].as_array().unwrap();
    assert!(!sessions.is_empty(), "the capture holds a TLS handshake");
    for session in sessions {
        let server = &session["server"];
        // The retained JA3S raw list "771,4865,43-51" pairs with the wire
        // order the JA4S hash covers: TLS 1.3, two extensions, no ALPN, and
        // the selected cipher 0x1301.
        assert_eq!(server["ja3s_raw"], "771,4865,43-51");
        assert_eq!(server["ja4s"], "t130200_1301_a56c5b993250");
    }
    // Fingerprints are verbose technical details, so only -v names them in text.
    let rendered = common::run_success(&["analyze", "tls", path_text(&capture), "-v"]);
    let text = String::from_utf8_lossy(&rendered.stdout);
    assert!(
        text.contains("ja4s=t130200_1301_a56c5b993250"),
        "text rendering names the server fingerprint: {text}"
    );
}
