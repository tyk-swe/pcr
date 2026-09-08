// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical DNS query encoding.

use bytes::Bytes;

use super::name::{canonical_query_name, encode_name};
use crate::dns::{CLASS_IN, FLAG_RECURSION_DESIRED, HEADER_BYTES};

/// Constructs one standard IN-class DNS query without resolver or I/O side
/// effects. Absent EDNS settings preserve the plain query bytes; settings
/// append one option-free EDNS v0 OPT record after validation.
pub fn encode_query(
    query_name: &str,
    query_type: crate::dns::QueryType,
    transaction_id: u16,
    recursion_desired: bool,
    edns: Option<crate::dns::EdnsRequest>,
) -> Result<Bytes, crate::dns::error::WireError> {
    if let Some(edns) = edns {
        edns.validate()?;
    }
    let query_name = canonical_query_name(query_name)?;
    let mut message = Vec::with_capacity(
        HEADER_BYTES
            .saturating_add(query_name.len())
            .saturating_add(5)
            .saturating_add(if edns.is_some() { 11 } else { 0 }),
    );
    message.extend_from_slice(&transaction_id.to_be_bytes());
    let flags = if recursion_desired {
        FLAG_RECURSION_DESIRED
    } else {
        0
    };
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&u16::from(edns.is_some()).to_be_bytes());
    encode_name(&query_name, &mut message)?;
    message.extend_from_slice(&query_type.code().to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    if let Some(edns) = edns {
        message.push(0); // Root owner.
        message.extend_from_slice(&41u16.to_be_bytes()); // OPT.
        message.extend_from_slice(&edns.udp_payload_size.to_be_bytes());
        message.extend_from_slice(&[0, 0]); // Extended RCODE and EDNS version 0.
        let flags = if edns.dnssec_ok { 0x8000u16 } else { 0 };
        message.extend_from_slice(&flags.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes()); // No options.
    }
    Ok(Bytes::from(message))
}
