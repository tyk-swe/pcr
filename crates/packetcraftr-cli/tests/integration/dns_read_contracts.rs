// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::common;
use common::{parse_json, run};

#[test]
fn application_budget_event_payloads() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let expected_text = concat!(
        "DNS udp:0 message=1 status=complete 192.0.2.53:53 -> 198.51.100.8:49152 frames=1\n",
        "  dns question: example.test. type=1 class=1\n",
        "  dns answer: example.test. type=1 class=1 ttl=60 {address=192.0.2.8,kind=a}\n",
        "  dns authority: example.test. type=2 class=1 ttl=300 {kind=ns,name=ns.example.test.}\n",
        "  dns additional: example.test. type=65000 class=1 ttl=7 {kind=unknown,rdata=ff00c0ff,type=65000}\n",
        "  dns additional: . type=41 class=1232 ttl=16810048 {dnssec_ok=true,extended_response_code=1,flags=32832,kind=opt,options={code=12,data=00ff01},udp_payload_size=1232,version=0}\n",
        "  transaction id=4660 status=orphan_response queries=none response=1 latest_latency=none\n",
        "1 DNS messages; 0 matched and 0 unanswered transactions in 1 captured frames\n",
    );
    common::application_output::assert_exact_budget(
        "dns-read",
        &path,
        &[
            ("dns_message", "messages"),
            ("dns_transaction", "transactions"),
            ("dns_stream_issue", "issues"),
        ],
        expected_text,
        "application output exceeds --max-application-output-bytes",
        &[],
    );
}

#[test]
fn zero_application_msg_limit_usage_error() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/dns-response.pcap");
    let path = path.to_str().unwrap();
    let output = run(&[
        "--output",
        "json",
        "dns-read",
        path,
        "--max-application-messages",
        "0",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let error = &parse_json(&output)["error"];
    assert_eq!(error["code"], "cli.analysis_limit");
    assert_eq!(error["kind"], "usage");
    assert!(
        error["message"].as_str().unwrap().contains("max_messages"),
        "{error}"
    );
}
