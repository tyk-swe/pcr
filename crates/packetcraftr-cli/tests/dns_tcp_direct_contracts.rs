// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{parse_json, run};

#[test]
fn direct_tcp_reject_before_conn() {
    for options in [
        vec!["--udp-only"],
        vec!["--source-port", "45000"],
        vec!["--interface", "missing-fixture-interface"],
        vec!["--source", "127.0.0.1"],
        vec!["--link-mode", "layer2"],
    ] {
        let mut arguments = vec![
            "--output",
            "json",
            "dns",
            "127.0.0.1",
            "example.test",
            "--tcp",
        ];
        arguments.extend(options);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2));
        parse_json(&output);
    }
}
