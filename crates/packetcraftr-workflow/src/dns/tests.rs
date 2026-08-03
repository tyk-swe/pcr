// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use super::engine::{dns_source_port, validate_dns_execution};
use super::*;
use crate::kernel::policy_authorizer::PolicyAuthorizer;
use crate::target::Authorized;
use evidence_validation::{NoopClock, ScriptedResolver, TimeoutExecutor};
use outcome::{PayloadExecutor, single_attempt_request};
use packetcraftr_capture::LinkType;
use packetcraftr_client::policy::Policy as TrafficPolicy;
use packetcraftr_client::target::{
    Error as TargetResolutionError, Hostname, Resolver as HostnameResolver,
};
use packetcraftr_core::error::Classified;
use packetcraftr_packet::semantics::BuiltinProtocol;
use packetcraftr_protocol::builtin::registry as default_registry;
use packetcraftr_protocol::icmp::{Icmpv4, Icmpv6};
use std::result::Result;

fn wire_name(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    if name == "." {
        bytes.push(0);
        return bytes;
    }
    for label in name.strip_suffix('.').unwrap_or(name).split('.') {
        assert!(!label.is_empty());
        bytes.push(u8::try_from(label.len()).expect("fixture label length fits in one byte"));
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes
}

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

#[derive(Clone)]
struct FixtureRecord {
    owner: Vec<u8>,
    type_code: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

impl FixtureRecord {
    fn in_class(owner: &str, type_code: u16, rdata: Vec<u8>) -> Self {
        Self {
            owner: wire_name(owner),
            type_code,
            class: DNS_CLASS_IN,
            ttl: 60,
            rdata,
        }
    }

    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.owner);
        output.extend_from_slice(&self.type_code.to_be_bytes());
        output.extend_from_slice(&self.class.to_be_bytes());
        output.extend_from_slice(&self.ttl.to_be_bytes());
        output.extend_from_slice(&u16::try_from(self.rdata.len()).unwrap().to_be_bytes());
        output.extend_from_slice(&self.rdata);
    }
}

fn fixture_response(
    transaction_id: u16,
    flags: u16,
    query_name: &str,
    query_type: DnsQueryType,
    answers: &[FixtureRecord],
    authorities: &[FixtureRecord],
    additionals: &[FixtureRecord],
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&transaction_id.to_be_bytes());
    output.extend_from_slice(&(DNS_FLAG_RESPONSE | flags).to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes());
    output.extend_from_slice(&u16::try_from(authorities.len()).unwrap().to_be_bytes());
    output.extend_from_slice(&u16::try_from(additionals.len()).unwrap().to_be_bytes());
    output.extend_from_slice(&wire_name(query_name));
    output.extend_from_slice(&query_type.code().to_be_bytes());
    output.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    for record in answers.iter().chain(authorities).chain(additionals) {
        record.encode(&mut output);
    }
    output
}

mod correlation;
mod evidence_validation;
mod outcome;
mod policy_retry;
mod wire_format;
mod wire_record;
