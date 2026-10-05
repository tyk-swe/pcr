// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use serde_json::Value;

use common::{parse_json, parse_ndjson, run};

#[test]
fn offline_fuzz_bounded_stable_rejects() {
    let packet = "ipv4(src=192.0.2.1,dst=198.51.100.2)/\
                  udp(sport=12345,dport=9)/raw(text=hello)";
    let arguments = [
        "--output",
        "json",
        "fuzz",
        "--packet",
        packet,
        "--seed",
        "7",
        "--cases",
        "32",
        "--max-field-bytes",
        "32",
        "--max-shrink-steps",
        "3",
    ];
    let first = run(&arguments);
    let second = run(&arguments);
    assert!(first.status.success(), "{:?}", first.stderr);
    assert!(second.status.success(), "{:?}", second.stderr);
    let mut documents = [parse_json(&first), parse_json(&second)];
    for document in &mut documents {
        assert!(document["stats"]["elapsed"].is_object(), "{document}");
        document["stats"]["elapsed"] = Value::Null;
    }
    let [value, repeated] = documents;
    assert_eq!(value, repeated);
    assert_eq!(value["result"]["cases_generated"], 32);
    let built = value["result"]["cases_built"].as_u64().expect("count");
    let rejected = value["result"]["cases_rejected"].as_u64().expect("count");
    assert_eq!(built + rejected, 32);
    assert!(built > 0);
    assert!(rejected > 0);

    let permissive = run(&[
        "--output",
        "ndjson",
        "fuzz",
        "--packet",
        packet,
        "--seed",
        "11",
        "--first-case",
        "100",
        "--cases",
        "8",
        "--mode",
        "permissive",
        "--strategy",
        "malformed,random",
        "--field",
        "0.ttl",
        "--field",
        "2.bytes",
        "--max-field-bytes",
        "16",
        "--max-shrink-steps",
        "2",
    ]);
    assert!(permissive.status.success(), "{:?}", permissive.stderr);
    let records = parse_ndjson(&permissive);
    assert_eq!(records.len(), 9);
    assert_eq!(
        records.last().expect("terminal record")["event"],
        "complete"
    );
}

#[test]
fn offline_fuzz_reject_live_opts_limits() {
    let base = ["fuzz", "--packet", "raw(text=hi)", "--cases", "1"];
    for live_only in [
        &["--allow-permissive-live"][..],
        &["--allow-malformed-live"][..],
        &["--destination", "127.0.0.1"],
        &["--timeout-ms", "1"],
        &["--rate", "1"],
        &["--interface", "1"],
        &["--source", "127.0.0.1"],
        &["--link-mode", "layer3"],
        &["--max-queue-frames", "1"],
        &["--max-captured-bytes", "64"],
        &["--snap-length", "64"],
        &["--overflow-policy", "drop-newest"],
        &["--allow-public-destinations"],
        &["--allow-permissive-packets"],
        &["--allow-source-spoofing"],
        &["--allow-destination", "192.0.2.0/24"],
        &["--max-packets", "1"],
        &["--max-bytes", "64"],
    ] {
        let arguments = base
            .iter()
            .copied()
            .chain(live_only.iter().copied())
            .collect::<Vec<_>>();
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--live"),
            "{arguments:?}: {:?}",
            output.stderr
        );
    }

    let offline = run(&[
        "--output",
        "json",
        "fuzz",
        "--packet",
        "raw(text=hi)",
        "--cases",
        "1",
        "--max-packet-bytes",
        "64",
    ]);
    assert!(offline.status.success(), "{:?}", offline.stderr);
}
