// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::model::DnsQueryType;
use super::super::{DNS_CLASS_IN, DNS_FLAG_RESPONSE};

pub(super) fn wire_name(name: &str) -> Vec<u8> {
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

#[derive(Clone)]
pub(super) struct FixtureRecord {
    pub(super) owner: Vec<u8>,
    pub(super) type_code: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) rdata: Vec<u8>,
}

impl FixtureRecord {
    pub(super) fn in_class(owner: &str, type_code: u16, rdata: Vec<u8>) -> Self {
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

pub(super) fn fixture_response(
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
