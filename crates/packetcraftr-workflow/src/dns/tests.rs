// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use packetcraftr_packet::semantics::BuiltinProtocol;

use super::model::{DnsProbe, DnsQueryType};
use super::wire::encode_dns_query;

#[test]
fn dns_probe_uses_typed_port_53_and_raw_custom_payloads() {
    let query = encode_dns_query("example.test", DnsQueryType::A, 7, true).unwrap();
    let standard_probe = DnsProbe {
        attempt: 1,
        server_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        server_port: 53,
        source_port: 50_000,
        transaction_id: 7,
        query_name: "example.test.".to_owned(),
        query_type: DnsQueryType::A,
        query: query.clone(),
    };
    let standard = standard_probe.packet();
    assert_eq!(standard.len(), 3);
    assert_eq!(
        BuiltinProtocol::of(standard.layer(2).unwrap()),
        Some(BuiltinProtocol::Dns)
    );

    let custom = DnsProbe {
        server_port: 5353,
        ..standard_probe
    }
    .packet();
    assert_eq!(
        BuiltinProtocol::of(custom.layer(2).unwrap()),
        Some(BuiltinProtocol::Raw)
    );
}

mod correlation;
mod evidence_validation;
mod outcome;
mod policy_retry;
mod support;
mod wire_format;
mod wire_record;
