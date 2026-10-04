// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::protocol::application::dns::Error as DecodeError;

use packetcraftr::dns::{self, MessageLimits as Limits, QueryType, wire};

const ID: u16 = 0x4a5b;
const RESPONSE: u16 = 0x8000;

#[derive(Clone)]
struct WireRecord {
    owner: Vec<u8>,
    type_code: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

fn name(value: &str) -> Vec<u8> {
    if value == "." {
        return vec![0];
    }
    let mut output = Vec::new();
    for label in value.trim_end_matches('.').split('.') {
        output.push(u8::try_from(label.len()).expect("fixture label fits DNS length"));
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    output
}

fn compressed_owner() -> Vec<u8> {
    vec![0xc0, 0x0c]
}

fn record(type_code: u16, rdata: Vec<u8>) -> WireRecord {
    WireRecord {
        owner: compressed_owner(),
        type_code,
        class: 1,
        ttl: 300,
        rdata,
    }
}

fn push_record(message: &mut Vec<u8>, record: &WireRecord) {
    message.extend_from_slice(&record.owner);
    message.extend_from_slice(&record.type_code.to_be_bytes());
    message.extend_from_slice(&record.class.to_be_bytes());
    message.extend_from_slice(&record.ttl.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(record.rdata.len())
            .expect("fixture RDATA fits u16")
            .to_be_bytes(),
    );
    message.extend_from_slice(&record.rdata);
}

fn response(
    query_name: &str,
    query_type: QueryType,
    flags: u16,
    answers: &[WireRecord],
    authorities: &[WireRecord],
    additionals: &[WireRecord],
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&ID.to_be_bytes());
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    for count in [answers.len(), authorities.len(), additionals.len()] {
        message.extend_from_slice(
            &u16::try_from(count)
                .expect("fixture record count fits u16")
                .to_be_bytes(),
        );
    }
    message.extend_from_slice(&name(query_name));
    message.extend_from_slice(&query_type.code().to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    for section in [answers, authorities, additionals] {
        for record in section {
            push_record(&mut message, record);
        }
    }
    message
}

#[test]
fn canonical_name_reject_wire_chars() {
    assert_eq!(
        dns::wire::canonical_query_name("*.SRV_example.test."),
        Ok("*.srv_example.test.".to_owned())
    );
    for invalid in [
        "".to_owned(),
        "bad..name".to_owned(),
        "bad name".to_owned(),
        "éxample.test".to_owned(),
        format!("{}.test", "a".repeat(64)),
        (0..4).map(|_| "a".repeat(63)).collect::<Vec<_>>().join("."),
    ] {
        assert!(
            dns::wire::canonical_query_name(&invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn record_limits_trailing_bad_rdata_reject() {
    let base = response(
        "example.test.",
        QueryType::A,
        RESPONSE,
        &[record(1, vec![192, 0, 2, 1])],
        &[],
        &[],
    );
    let limits = Limits {
        max_records: 0,
        ..Limits::default()
    };
    assert!(matches!(
        dns::wire::decode_response(&base, "example.test", QueryType::A, ID, limits),
        Err(wire::Error::Decode(DecodeError::RecordLimit {
            actual: 1,
            limit: 0
        }))
    ));

    let mut trailing = base;
    trailing.push(0xff);
    assert!(matches!(
        dns::wire::decode_response(
            &trailing,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(wire::Error::Decode(DecodeError::TrailingBytes {
            remaining: 1
        }))
    ));

    for (query_type, malformed) in [
        (QueryType::A, record(1, vec![1, 2, 3])),
        (QueryType::AAAA, record(28, vec![0; 15])),
        (QueryType::MX, record(15, vec![0, 1])),
        (QueryType::SRV, record(33, vec![0; 6])),
        (QueryType::TXT, record(16, vec![3, b'a'])),
    ] {
        let message = response(
            "example.test.",
            query_type,
            RESPONSE,
            &[malformed],
            &[],
            &[],
        );
        assert!(matches!(
            dns::wire::decode_response(&message, "example.test", query_type, ID, Limits::default()),
            Err(wire::Error::Decode(DecodeError::InvalidRdata { .. }))
        ));
    }
}

#[test]
fn txt_limits_safety_enforced() {
    let message = response(
        "example.test.",
        QueryType::TXT,
        RESPONSE,
        &[record(16, vec![1, b'a', 1, b'b'])],
        &[],
        &[],
    );
    let string_limit = Limits {
        max_txt_strings: 1,
        ..Limits::default()
    };
    assert!(matches!(
        dns::wire::decode_response(&message, "example.test", QueryType::TXT, ID, string_limit),
        Err(wire::Error::Decode(DecodeError::TxtStringLimit {
            limit: 1
        }))
    ));
    let byte_limit = Limits {
        max_txt_bytes: 1,
        ..Limits::default()
    };
    assert!(matches!(
        dns::wire::decode_response(&message, "example.test", QueryType::TXT, ID, byte_limit),
        Err(wire::Error::Decode(DecodeError::TxtByteLimit { limit: 1 }))
    ));

    let pointer_limit = Limits {
        max_name_pointers: 0,
        ..Limits::default()
    };
    let pointer_message = response(
        "example.test.",
        QueryType::A,
        RESPONSE,
        &[record(1, vec![192, 0, 2, 1])],
        &[],
        &[],
    );
    assert!(matches!(
        dns::wire::decode_response(
            &pointer_message,
            "example.test",
            QueryType::A,
            ID,
            pointer_limit
        ),
        Err(wire::Error::Decode(DecodeError::PointerLimit { limit: 0 }))
    ));

    for (question, expected) in [
        (vec![0xc0, 0x0c], DecodeError::SelfPointer { offset: 12 }),
        (
            vec![0xc0, 0xff],
            DecodeError::PointerOutOfBounds {
                pointer: 255,
                length: 18,
            },
        ),
        (
            vec![0x40, 0],
            DecodeError::ReservedLabelLength { offset: 12 },
        ),
    ] {
        let mut malformed = Vec::new();
        malformed.extend_from_slice(&ID.to_be_bytes());
        malformed.extend_from_slice(&RESPONSE.to_be_bytes());
        malformed.extend_from_slice(&1_u16.to_be_bytes());
        malformed.extend_from_slice(&[0; 6]);
        malformed.extend_from_slice(&question);
        malformed.extend_from_slice(&QueryType::A.code().to_be_bytes());
        malformed.extend_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            dns::wire::decode_response(
                &malformed,
                "example.test",
                QueryType::A,
                ID,
                Limits::default()
            ),
            Err(wire::Error::Decode(expected))
        );
    }
}
