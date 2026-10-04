// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};

use packetcraftr::{Stats, dns};
use packetcraftr_cli::output::dns as dns_output;
use packetcraftr_cli::output::envelope::Published;

const TRANSACTION_ID: u16 = 0x4a5b;

#[derive(Clone)]
struct WireRecord {
    owner: Vec<u8>,
    type_code: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

#[test]
fn dns_timeout_output_omits_resp_only_fields() {
    let Published {
        result: output,
        diagnostics,
        ..
    } = Published::<dns_output::Report>::try_from({
        let response: Option<packetcraftr::dns::ValidatedResponse> = None;
        packetcraftr::dns::Aggregate::new(
            packetcraftr::dns::Report {
                server: "resolver.example.test".to_owned(),
                server_port: 53,
                resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
                query_name: "example.test".to_owned(),
                query_type: dns::QueryType::new(0),
                transaction_id: TRANSACTION_ID,
                stats: Stats::default(),
                completion: packetcraftr::dns::Completion::new(
                    packetcraftr::dns::Outcome::Timeout,
                    false,
                    None,
                    response.as_ref().map(|response| response.metadata.clone()),
                )
                .unwrap(),
            },
            response,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    })
    .expect("timeout output converts");
    assert!(diagnostics.is_empty());
    assert!(output.answers.is_empty());

    let json = serde_json::to_value(output).expect("timeout output serializes");
    assert_eq!(json["query_type"], 0);
    for response_only in [
        "response_code",
        "response_code_name",
        "edns",
        "authoritative",
        "truncated",
        "recursion_desired",
        "recursion_available",
        "authenticated_data",
        "checking_disabled",
    ] {
        assert!(
            json.get(response_only).is_none(),
            "{response_only} must be omitted"
        );
    }

    let Published {
        result: complete,
        diagnostics,
        ..
    } = Published::<dns_output::Event>::from(packetcraftr::dns::Report {
        server: "resolver.example.test".to_owned(),
        server_port: 53,
        resolved_addresses: Vec::new(),
        query_name: "example.test".to_owned(),
        query_type: dns::QueryType::new(0),
        transaction_id: TRANSACTION_ID,
        stats: Stats::default(),
        completion: packetcraftr::dns::Completion::new(
            packetcraftr::dns::Outcome::Timeout,
            false,
            None,
            None,
        )
        .unwrap(),
    });
    assert!(diagnostics.is_empty());
    let complete = serde_json::to_value(complete).expect("complete timeout serializes");
    assert!(complete.get("response_code").is_none());
    assert_eq!(complete["rejected_record_count"], 0);
}
