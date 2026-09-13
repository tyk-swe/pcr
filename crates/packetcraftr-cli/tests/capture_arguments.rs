// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod support;
use support::{parse_json, run};
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
