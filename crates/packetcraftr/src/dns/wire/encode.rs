// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical DNS query encoding.

use bytes::Bytes;

use super::name::{canonical_query_name, encode_name};
use crate::dns::{CLASS_IN, FLAG_RECURSION_DESIRED, HEADER_BYTES};

/// Constructs one standard IN-class DNS query without resolver or I/O side
/// effects.
pub fn encode_query(
    query_name: &str,
    query_type: crate::dns::model::QueryType,
    transaction_id: u16,
    recursion_desired: bool,
) -> Result<Bytes, crate::dns::error::WireError> {
    let query_name = canonical_query_name(query_name)?;
    let mut message = Vec::with_capacity(
        HEADER_BYTES
            .saturating_add(query_name.len())
            .saturating_add(5),
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
    message.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&query_name, &mut message)?;
    message.extend_from_slice(&query_type.code().to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(Bytes::from(message))
}
