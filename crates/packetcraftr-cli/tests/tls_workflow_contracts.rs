// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

mod common;
#[path = "common/tls_capture.rs"]
mod tls_capture;

use common::{path_text, run};

#[test]
fn limit_failures_are_reported_before_any_capture_is_read() {
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
