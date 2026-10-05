// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use common::{parse_json, run};

#[test]
fn mismatch_conflict_fail_before_input() {
    for options in [
        vec!["--decode-as", "tcp.port=53:vxlan"],
        vec!["--decode-as", "udp.port=0:dns"],
        vec!["--decode-as", "udp.port=65536:dns"],
        vec!["--decode-as", "udp.port=53:unknown"],
        vec![
            "--decode-as",
            "udp.port=53:dns",
            "--decode-as",
            "udp.port=53:raw",
        ],
        vec!["--tls-port", "4433", "--decode-as", "tcp.port=4433:raw"],
    ] {
        let mut args = vec!["--output", "json", "dissect"];
        args.extend(options);
        let output = run(&args);
        assert!(!output.status.success());
        assert_eq!(parse_json(&output)["error"]["code"], "cli.decode_as");
    }
}
