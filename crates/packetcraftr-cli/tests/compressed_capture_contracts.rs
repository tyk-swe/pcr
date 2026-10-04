// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::run;

#[test]
fn invalid_compression_reject_before_live_work() {
    for command in [
        vec!["capture", "--interface", "missing-interface"],
        vec!["read", "/missing/capture"],
        vec!["send", "--packet", "invalid"],
        vec!["fragment", "--mtu", "128", "--packet", "invalid"],
    ] {
        let mut arguments = vec!["--output", "text"];
        arguments.extend(command);
        arguments.extend(["--compression", "gzip"]);
        let output = run(&arguments);
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("--compression requires")
        );
    }
}
