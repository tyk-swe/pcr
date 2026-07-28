// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical DNS query encoding.

use super::super::{
    Bytes, DNS_CLASS_IN, DNS_FLAG_RECURSION_DESIRED, DNS_HEADER_BYTES, DnsQueryType, DnsWireError,
};
use super::name::{canonical_query_name, encode_name};

/// Constructs one standard IN-class DNS query without resolver or I/O side
/// effects.
pub fn encode_dns_query(
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    recursion_desired: bool,
) -> Result<Bytes, DnsWireError> {
    let query_name = canonical_query_name(query_name)?;
    let mut message = Vec::with_capacity(DNS_HEADER_BYTES + query_name.len() + 5);
    message.extend_from_slice(&transaction_id.to_be_bytes());
    let flags = if recursion_desired {
        DNS_FLAG_RECURSION_DESIRED
    } else {
        0
    };
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&query_name, &mut message)?;
    message.extend_from_slice(&query_type.code().to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(Bytes::from(message))
}
