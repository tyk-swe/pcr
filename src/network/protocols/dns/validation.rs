// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::rr::{Name, RecordType};

pub(super) const DNS_HEADER_BYTES: usize = 12;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_TRUNCATED: u16 = 0x0200;
const DNS_RCODE_MASK: u16 = 0x000f;

pub(super) struct DnsHeaderSummary {
    pub(super) truncated: bool,
}

pub(super) fn inspect_dns_response_header(
    response: &[u8],
    expected_id: u16,
) -> Result<DnsHeaderSummary> {
    if response.len() < DNS_HEADER_BYTES {
        return Err(anyhow!(
            "DNS response too short: {} bytes, expected at least {} byte header",
            response.len(),
            DNS_HEADER_BYTES
        ));
    }

    let id = u16::from_be_bytes([response[0], response[1]]);
    let flags = u16::from_be_bytes([response[2], response[3]]);

    if flags & DNS_FLAG_RESPONSE == 0 {
        return Err(anyhow!(
            "Message type mismatch: expected Response, got Query"
        ));
    }

    let response_code = ResponseCode::from_low((flags & DNS_RCODE_MASK) as u8);
    if response_code != ResponseCode::NoError {
        return Err(anyhow!("DNS server returned error: {}", response_code));
    }

    if id != expected_id {
        return Err(anyhow!(
            "Transaction ID mismatch: expected {}, got {}",
            expected_id,
            id
        ));
    }

    Ok(DnsHeaderSummary {
        truncated: flags & DNS_FLAG_TRUNCATED != 0,
    })
}

pub(super) fn validate_dns_response(
    response: &[u8],
    expected_id: u16,
    expected_domain: &str,
    expected_type: RecordType,
) -> Result<Message> {
    let message = Message::from_vec(response)?;

    if message.message_type() != MessageType::Response {
        return Err(anyhow::anyhow!(
            "Message type mismatch: expected Response, got {:?}",
            message.message_type()
        ));
    }

    if message.response_code() != ResponseCode::NoError {
        return Err(anyhow::anyhow!(
            "DNS server returned error: {}",
            message.response_code()
        ));
    }

    if message.id() != expected_id {
        return Err(anyhow::anyhow!(
            "Transaction ID mismatch: expected {}, got {}",
            expected_id,
            message.id()
        ));
    }

    if message.queries().is_empty() {
        return Err(anyhow::anyhow!("Response contains no queries"));
    }

    let query = &message.queries()[0];
    let normalized_domain = if expected_domain.ends_with('.') {
        expected_domain.to_string()
    } else {
        format!("{}.", expected_domain)
    };
    let expected_name = Name::from_str(&normalized_domain).context("Invalid domain name")?;

    if *query.name() != expected_name {
        return Err(anyhow::anyhow!(
            "Query name mismatch: expected {}, got {}",
            expected_name,
            query.name()
        ));
    }

    if query.query_type() != expected_type {
        return Err(anyhow::anyhow!(
            "Query type mismatch: expected {}, got {}",
            expected_type,
            query.query_type()
        ));
    }

    Ok(message)
}
