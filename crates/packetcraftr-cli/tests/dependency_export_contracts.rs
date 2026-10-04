// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{parse_json, run};
#[test]
fn zero_ceiling_frame_limit_usage_error() {
    let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/http-stream.pcap");
    let source = source.to_str().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("selected.pcap");
    for limit in ["0", "1000001"] {
        let output = run(&[
            "--output",
            "json",
            "export",
            source,
            "--stream",
            "tcp:0",
            "--write",
            target.to_str().unwrap(),
            "--max-selected-frames",
            limit,
        ]);
        assert_eq!(output.status.code(), Some(2), "{limit}");
        let error = &parse_json(&output)["error"];
        assert_eq!(error["code"], "cli.analysis_limit", "{limit}");
        assert_eq!(error["kind"], "usage", "{limit}");
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("max_selected_frames"),
            "{error}"
        );
        assert!(!target.exists());
    }
}
