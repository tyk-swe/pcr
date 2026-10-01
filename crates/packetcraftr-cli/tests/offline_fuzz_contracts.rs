// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use serde_json::Value;

use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};

#[test]
fn offline_fuzz_is_bounded_reproducible_and_reports_rejections() {
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
fn offline_fuzz_rejects_live_only_options_and_has_an_independent_packet_limit() {
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

#[test]
fn fuzz_stream_preserves_cases_before_a_late_campaign_failure() {
    let output = run(&[
        "--output",
        "ndjson",
        "fuzz",
        "--packet",
        "raw(text=abcd)",
        "--field",
        "0.bytes",
        "--strategy",
        "bit-flip",
        "--cases",
        "3",
        "--max-cases",
        "3",
        "--max-packet-bytes",
        "32",
        "--max-total-bytes",
        "60",
        "--max-field-bytes",
        "16",
    ]);
    assert_eq!(output.status.code(), Some(6));
    let records = parse_ndjson(&output);
    assert_contiguous(&records);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["result"]["case"]["index"], 0);
    assert_eq!(records[1]["result"]["case"]["index"], 1);
    assert_eq!(records[2]["status"], "error");
    assert_eq!(records[2]["sequence"], 2);
    assert!(records.iter().all(|record| record["event"] != "complete"));
}

#[test]
fn fuzz_aggregate_is_collected_from_the_streamed_case_path() {
    let common = [
        "fuzz",
        "--packet",
        "raw(text=abcd)",
        "--field",
        "0.bytes",
        "--strategy",
        "bit-flip",
        "--cases",
        "3",
        "--max-cases",
        "3",
        "--max-packet-bytes",
        "32",
        "--max-total-bytes",
        "100",
        "--max-field-bytes",
        "16",
    ];
    let aggregate_arguments = ["--output", "json"]
        .into_iter()
        .chain(common)
        .collect::<Vec<_>>();
    let stream_arguments = ["--output", "ndjson"]
        .into_iter()
        .chain(common)
        .collect::<Vec<_>>();
    let aggregate = parse_json(&run_success(&aggregate_arguments));
    let streamed = parse_ndjson(&run_success(&stream_arguments));
    let streamed_cases = streamed[..streamed.len() - 1]
        .iter()
        .map(|record| record["result"]["case"].clone())
        .collect::<Vec<_>>();
    let complete = streamed.last().expect("fuzz completion record");

    assert_eq!(
        aggregate["result"]["cases"]
            .as_array()
            .expect("aggregate fuzz cases"),
        &streamed_cases
    );
    for field in ["cases_generated", "cases_built", "cases_rejected"] {
        assert_eq!(aggregate["result"][field], complete["result"][field]);
    }
    let mut statistics = [aggregate["stats"].clone(), complete["stats"].clone()];
    for stats in &mut statistics {
        assert!(stats["elapsed"].is_object(), "{stats}");
        stats["elapsed"] = Value::Null;
    }
    let [aggregate_stats, complete_stats] = statistics;
    assert_eq!(aggregate_stats, complete_stats);
}

const SHIFTED_PACKET: &str = "vlan(vlan_id=7)/ipv4(src=192.0.2.1,dst=192.0.2.2)/\
                              ipv4(src=198.51.100.1,dst=198.51.100.2)/udp(dport=9)/raw(text=hi)";

fn fuzz_cases(fields: &[&str]) -> Vec<Value> {
    let mut args = vec![
        "--output",
        "ndjson",
        "fuzz",
        "--packet",
        SHIFTED_PACKET,
        "--seed",
        "5",
        "--cases",
        "24",
        "--strategy",
        "boundary,random",
    ];
    for field in fields {
        args.extend(["--field", field]);
    }
    let records = parse_ndjson(&run_success(&args));
    records
        .iter()
        .filter(|record| record["event"] != "complete")
        .map(|record| record["result"]["case"].clone())
        .collect()
}

fn mutated(cases: &[Value]) -> std::collections::BTreeSet<(u64, String, String)> {
    cases
        .iter()
        .map(|case| {
            let mutation = &case["mutation"];
            (
                mutation["layer"].as_u64().expect("layer index"),
                mutation["protocol"].as_str().expect("protocol").to_owned(),
                mutation["field"].as_str().expect("field").to_owned(),
            )
        })
        .collect()
}

#[test]
fn fuzz_fields_resolve_by_protocol_and_report_numeric_layer_indexes() {
    let by_name = fuzz_cases(&["ipv4.ttl"]);
    assert_eq!(by_name.len(), 24);
    assert_eq!(
        mutated(&by_name),
        [(1, "ipv4".to_owned(), "ttl".to_owned())].into()
    );
    // the numeric spelling selects the same layer and reproduces identically
    assert_eq!(by_name, fuzz_cases(&["1.ttl"]));
    // selectors are case-insensitive in the protocol and in the field
    assert_eq!(by_name, fuzz_cases(&["IPV4.TTL"]));
    assert_eq!(by_name, fuzz_cases(&["1.TTL"]));

    let inner = fuzz_cases(&["ipv4#2.ttl", "udp.destination_port"]);
    assert_eq!(
        mutated(&inner),
        [
            (2, "ipv4".to_owned(), "ttl".to_owned()),
            (3, "udp".to_owned(), "destination_port".to_owned())
        ]
        .into()
    );
    assert_eq!(inner, fuzz_cases(&["2.ttl", "3.destination_port"]));
}

#[test]
fn fuzz_wildcards_expand_over_layers_and_fields() {
    let every_ttl = mutated(&fuzz_cases(&["*.ttl"]));
    assert_eq!(
        every_ttl,
        [
            (1, "ipv4".to_owned(), "ttl".to_owned()),
            (2, "ipv4".to_owned(), "ttl".to_owned())
        ]
        .into()
    );
    let udp = mutated(&fuzz_cases(&["udp.*"]));
    assert!(udp.len() > 1);
    assert!(
        udp.iter()
            .all(|(layer, protocol, _)| *layer == 3 && protocol == "udp")
    );
}

#[test]
fn unresolvable_fuzz_fields_are_typed_usage_errors() {
    for field in [
        "ipv4#3.ttl",
        "ipv4#0.ttl",
        "nosuchprotocol.ttl",
        "*.nosuchfield",
        "dns.*",
    ] {
        let output = run(&[
            "--output",
            "json",
            "fuzz",
            "--packet",
            SHIFTED_PACKET,
            "--field",
            field,
        ]);
        assert_eq!(output.status.code(), Some(2), "{field}");
        assert_eq!(
            parse_json(&output)["error"]["code"],
            "cli.selector",
            "{field}"
        );
    }
}

#[test]
fn live_fuzz_resolves_protocol_selectors_before_the_policy_refuses_the_destination() {
    let live = |field: &str| {
        run(&[
            "--output",
            "json",
            "fuzz",
            "--packet",
            "vlan(vlan_id=7)/ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--field",
            field,
            "--cases",
            "1",
            "--live",
        ])
    };
    // a selector the recipe satisfies reaches the policy, which refuses the
    // public destination before any interface or socket is touched
    let refused = live("udp.dport");
    assert_eq!(refused.status.code(), Some(6), "{:?}", refused.stderr);
    assert_eq!(
        parse_json(&refused)["error"]["code"],
        "policy.public_destination"
    );
    // one it cannot satisfy is a usage error ahead of the policy
    let unresolved = live("ipv4#2.ttl");
    assert_eq!(unresolved.status.code(), Some(2));
    assert_eq!(parse_json(&unresolved)["error"]["code"], "cli.selector");
}
