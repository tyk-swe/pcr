// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::name::canonical_query_name;
use crate::dns::CLASS_IN;

/// Constructs one standard IN-class DNS query without resolver or I/O side
/// effects. Absent EDNS settings preserve the plain query bytes; settings
/// append one option-free EDNS v0 OPT record after validation.
pub fn encode_query(
    query_name: &str,
    query_type: crate::dns::QueryType,
    transaction_id: u16,
    recursion_desired: bool,
    edns: Option<crate::dns::EdnsRequest>,
) -> Result<Bytes, super::Error> {
    use packetcraftr_core::protocol::application::dns::{
        Dns, Edns, Name, Question, Record, RecordValue,
    };
    if let Some(edns) = edns {
        edns.validate()?;
    }
    let query_name = canonical_query_name(query_name)?;
    let mut message = Dns::default();
    message.id = transaction_id;
    message.recursion_desired = recursion_desired;
    message.questions.push(Question {
        name: query_name.parse()?,
        query_type: query_type.code(),
        class: CLASS_IN,
    });
    if let Some(edns) = edns {
        message.additionals.push(Record {
            owner: Name::root(),
            class: edns.udp_payload_size,
            ttl: if edns.dnssec_ok { 0x8000 } else { 0 },
            value: RecordValue::Opt(Edns {
                udp_payload_size: edns.udp_payload_size,
                extended_response_code: 0,
                version: 0,
                dnssec_ok: edns.dnssec_ok,
                flags: if edns.dnssec_ok { 0x8000 } else { 0 },
                options: Vec::new(),
            }),
        });
    }
    message.to_wire().map_err(|error| match error {
        packetcraftr_core::protocol::application::dns::Error::Encode(source) => {
            super::Error::Encode(source)
        }
        error => super::Error::Decode(error),
    })
}
