// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use packetcraftr_core::protocol::application::dns::{Dns, Edns, Question, Record, RecordValue};

use super::decode::{decode_response, decode_tcp_frame};
use super::encode::encode_query;
use super::error::Error;
use super::name::canonical_query_name;
use crate::dns::{EdnsRequest, MessageLimits, QueryType};

const ID: u16 = 0x1234;

fn a_answer() -> Record {
    Record {
        owner: "example.test.".parse().unwrap(),
        class: 1,
        ttl: 60,
        value: RecordValue::A(Ipv4Addr::new(192, 0, 2, 8)),
    }
}

fn opt(extended_response_code: u8, version: u8) -> Record {
    Record::opt(Edns {
        udp_payload_size: 1232,
        extended_response_code,
        version,
        dnssec_ok: false,
        flags: 0,
        options: Vec::new(),
    })
}

fn message(edit: impl FnOnce(&mut Dns)) -> Vec<u8> {
    let mut dns = Dns::default();
    dns.id = ID;
    dns.response = true;
    dns.authoritative_answer = true;
    dns.recursion_desired = true;
    dns.recursion_available = true;
    dns.questions.push(Question {
        name: "example.test.".parse().unwrap(),
        query_type: 1,
        class: 1,
    });
    dns.answers.push(a_answer());
    edit(&mut dns);
    dns.to_wire().unwrap().to_vec()
}

fn valid_response() -> Vec<u8> {
    message(|_| {})
}

fn mutate_flags(bytes: &mut [u8], change: impl Fn(u16) -> u16) {
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    bytes[2..4].copy_from_slice(&change(flags).to_be_bytes());
}

fn decode(bytes: &[u8]) -> Result<crate::dns::ValidatedResponse, Error> {
    decode_response(
        bytes,
        "example.test",
        QueryType::A,
        ID,
        MessageLimits::default(),
    )
}

#[test]
fn encode_query_builds_the_exact_wire_question() {
    let bytes = encode_query("example.test", QueryType::A, ID, true, None).unwrap();
    let mut expected = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7];
    expected.extend_from_slice(b"example");
    expected.push(4);
    expected.extend_from_slice(b"test");
    expected.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(bytes.as_ref(), expected.as_slice());

    let no_recursion = encode_query("example.test", QueryType::new(28), ID, false, None).unwrap();
    assert_eq!(&no_recursion[2..4], &[0, 0]);
    assert_eq!(&no_recursion[no_recursion.len() - 4..], &[0, 28, 0, 1]);
}

#[test]
fn encode_query_root_name_and_edns_additional() {
    let root = encode_query(".", QueryType::A, ID, false, None).unwrap();
    assert_eq!(root.len(), 17);
    assert_eq!(root[12], 0);

    let edns = EdnsRequest {
        udp_payload_size: 1232,
        dnssec_ok: true,
    };
    let bytes = encode_query("EXAMPLE.test", QueryType::A, ID, true, Some(edns)).unwrap();
    let decoded = Dns::from_wire_with_limits(bytes, MessageLimits::default().into()).unwrap();
    assert_eq!(decoded.additionals.len(), 1);
    match &decoded.additionals[0].value {
        RecordValue::Opt(value) => {
            assert_eq!(value.udp_payload_size, 1232);
            assert!(value.dnssec_ok);
            assert_eq!(value.flags, 0x8000);
        }
        other => panic!("expected OPT additional, found {other:?}"),
    }
    assert_eq!(decoded.additionals[0].ttl, 0x8000);

    let too_small = EdnsRequest {
        udp_payload_size: 511,
        dnssec_ok: false,
    };
    assert!(matches!(
        encode_query("example.test", QueryType::A, ID, true, Some(too_small)),
        Err(Error::InvalidEdns { .. })
    ));
}

#[test]
fn canonical_names_normalize_and_reject_bad_labels() {
    assert_eq!(
        canonical_query_name("Example.TEST").unwrap(),
        "example.test."
    );
    assert_eq!(
        canonical_query_name("example.test.").unwrap(),
        "example.test."
    );
    assert_eq!(canonical_query_name(".").unwrap(), ".");
    assert_eq!(
        canonical_query_name("_dmarc.example-test").unwrap(),
        "_dmarc.example-test."
    );
    assert!(canonical_query_name(&"a".repeat(63)).is_ok());
    for bad in ["", "a..b", "exa mple.test", "bad!.test"] {
        assert!(
            matches!(canonical_query_name(bad), Err(Error::InvalidName { .. })),
            "{bad:?} must be refused"
        );
    }
    assert!(matches!(
        canonical_query_name(&"a".repeat(64)),
        Err(Error::InvalidName { .. })
    ));
    let too_long = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(63),
    ]
    .join(".");
    assert!(matches!(
        canonical_query_name(&too_long),
        Err(Error::NameTooLong)
    ));
    let within = ["a".repeat(63), "b".repeat(63), "c".repeat(63)].join(".");
    assert!(canonical_query_name(&within).is_ok());
}

#[test]
fn decode_response_accepts_a_relevant_answer_and_metadata() {
    let bytes = message(|dns| {
        dns.authenticated_data = true;
        dns.checking_disabled = true;
        dns.rcode = 0;
    });
    let response = decode(&bytes).unwrap();
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].ttl, 60);
    assert_eq!(
        response.answers[0].value,
        RecordValue::A(Ipv4Addr::new(192, 0, 2, 8))
    );
    let metadata = response.metadata;
    assert_eq!(metadata.response_code, 0);
    assert!(metadata.authoritative);
    assert!(!metadata.truncated);
    assert!(metadata.recursion_desired);
    assert!(metadata.recursion_available);
    assert!(metadata.authenticated_data);
    assert!(metadata.checking_disabled);
    assert_eq!(metadata.rejected_record_count, 0);
    assert!(metadata.edns.is_none());
}

#[test]
fn decode_response_rejects_header_and_question_mismatches() {
    let mut not_response = valid_response();
    mutate_flags(&mut not_response, |flags| flags & !0x8000);
    assert_eq!(decode(&not_response), Err(Error::NotResponse));

    let mut opcode = valid_response();
    mutate_flags(&mut opcode, |flags| flags | (1 << 11));
    assert_eq!(decode(&opcode), Err(Error::UnsupportedOpcode { opcode: 1 }));

    let mut reserved = valid_response();
    mutate_flags(&mut reserved, |flags| flags | 0x0040);
    assert_eq!(decode(&reserved), Err(Error::ReservedHeaderBits));

    let mut wrong_id = valid_response();
    wrong_id[0..2].copy_from_slice(&0x9999u16.to_be_bytes());
    assert_eq!(
        decode(&wrong_id),
        Err(Error::TransactionIdMismatch {
            expected: ID,
            actual: 0x9999
        })
    );

    let mut no_question = valid_response();
    no_question[4..6].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        decode(&no_question),
        Err(Error::QuestionCount { actual: 0 })
    );

    let other_name = message(|dns| dns.questions[0].name = "other.test.".parse().unwrap());
    assert!(matches!(
        decode(&other_name),
        Err(Error::QuestionNameMismatch { .. })
    ));

    let other_type = message(|dns| dns.questions[0].query_type = 28);
    assert_eq!(
        decode(&other_type),
        Err(Error::QuestionTypeMismatch {
            expected: 1,
            actual: 28
        })
    );

    let other_class = message(|dns| dns.questions[0].class = 3);
    assert_eq!(
        decode(&other_class),
        Err(Error::QuestionClassMismatch { actual: 3 })
    );
}

#[test]
fn decode_response_bounds_truncation_and_rcode() {
    assert!(matches!(decode(&[0u8; 11]), Err(Error::Decode(_))));
    let limits = MessageLimits {
        max_message_bytes: 12,
        ..MessageLimits::default()
    };
    assert!(matches!(
        decode_response(&valid_response(), "example.test", QueryType::A, ID, limits),
        Err(Error::Decode(_))
    ));

    let mut truncated = valid_response();
    mutate_flags(&mut truncated, |flags| flags | 0x0200 | 3);
    let response = decode(&truncated).unwrap();
    assert!(response.metadata.truncated);
    assert_eq!(response.metadata.response_code, 3);
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert!(response.additionals.is_empty());

    let query_only = encode_query("example.test", QueryType::A, ID, true, None).unwrap();
    let mut as_response = query_only.to_vec();
    mutate_flags(&mut as_response, |flags| flags | 0x8000);
    let cut = &as_response[..as_response.len() - 3];
    assert!(matches!(decode(cut), Err(Error::Decode(_))));
}

#[test]
fn decode_response_validates_edns_placement_and_extended_rcode() {
    let extended = message(|dns| dns.additionals.push(opt(1, 0)));
    let response = decode(&extended).unwrap();
    assert_eq!(response.metadata.response_code, 16);
    assert!(response.metadata.edns.is_some());

    let duplicate = message(|dns| dns.additionals.extend([opt(0, 0), opt(0, 0)]));
    assert_eq!(decode(&duplicate), Err(Error::DuplicateEdns));

    let bad_version = message(|dns| dns.additionals.push(opt(0, 1)));
    assert_eq!(
        decode(&bad_version),
        Err(Error::UnsupportedEdnsVersion { version: 1 })
    );

    let in_answers = message(|dns| dns.answers.push(opt(0, 0)));
    assert!(matches!(
        decode(&in_answers),
        Err(Error::InvalidEdns { .. })
    ));

    let non_root = message(|dns| {
        let mut record = opt(0, 0);
        record.owner = "example.test.".parse().unwrap();
        dns.additionals.push(record);
    });
    assert!(matches!(decode(&non_root), Err(Error::InvalidEdns { .. })));
}

#[test]
fn decode_tcp_frame_checks_the_length_prefix() {
    let payload = valid_response();
    let mut frame = u16::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    let response = decode_tcp_frame(
        &frame,
        "example.test",
        QueryType::A,
        ID,
        MessageLimits::default(),
    )
    .unwrap();
    assert_eq!(response.answers.len(), 1);

    assert!(matches!(
        decode_tcp_frame(
            &[0],
            "example.test",
            QueryType::A,
            ID,
            MessageLimits::default()
        ),
        Err(Error::Decode(_))
    ));
    assert_eq!(
        decode_tcp_frame(
            &[0, 0],
            "example.test",
            QueryType::A,
            ID,
            MessageLimits::default()
        ),
        Err(Error::TcpFrameZeroLength)
    );
    let limits = MessageLimits {
        max_message_bytes: 10,
        ..MessageLimits::default()
    };
    let mut oversized = 20u16.to_be_bytes().to_vec();
    oversized.extend_from_slice(&[0u8; 20]);
    assert!(matches!(
        decode_tcp_frame(&oversized, "example.test", QueryType::A, ID, limits),
        Err(Error::Decode(_))
    ));
    assert_eq!(
        decode_tcp_frame(
            &[0, 5, 1, 2, 3],
            "example.test",
            QueryType::A,
            ID,
            MessageLimits::default()
        ),
        Err(Error::TcpFrameLength {
            declared: 5,
            actual: 3
        })
    );

    let mut truncated_payload = valid_response();
    mutate_flags(&mut truncated_payload, |flags| flags | 0x0200);
    let mut truncated_frame = u16::try_from(truncated_payload.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    truncated_frame.extend_from_slice(&truncated_payload);
    assert_eq!(
        decode_tcp_frame(
            &truncated_frame,
            "example.test",
            QueryType::A,
            ID,
            MessageLimits::default()
        ),
        Err(Error::TcpResponseTruncated)
    );
}

#[test]
fn only_correlation_mismatches_are_unrelated() {
    for error in [
        Error::TransactionIdMismatch {
            expected: 1,
            actual: 2,
        },
        Error::QuestionNameMismatch {
            expected: "a.".into(),
            actual: "b.".into(),
        },
        Error::QuestionTypeMismatch {
            expected: 1,
            actual: 28,
        },
        Error::QuestionClassMismatch { actual: 3 },
    ] {
        assert!(error.is_unrelated(), "{error:?} must be unrelated");
    }
    for error in [
        Error::NotResponse,
        Error::ReservedHeaderBits,
        Error::TcpFrameZeroLength,
        Error::DuplicateEdns,
        Error::NameTooLong,
    ] {
        assert!(!error.is_unrelated(), "{error:?} must stay related");
    }
}

#[test]
fn decode_response_reports_clear_flags_as_false() {
    let bytes = message(|dns| {
        dns.authoritative_answer = false;
        dns.recursion_desired = false;
        dns.recursion_available = false;
    });
    let metadata = decode(&bytes).unwrap().metadata;
    assert!(!metadata.authoritative);
    assert!(!metadata.truncated);
    assert!(!metadata.recursion_desired);
    assert!(!metadata.recursion_available);
    assert!(!metadata.authenticated_data);
    assert!(!metadata.checking_disabled);
}

#[test]
fn decode_accepts_messages_exactly_at_the_size_limit() {
    let payload = valid_response();
    let limits = MessageLimits {
        max_message_bytes: payload.len(),
        ..MessageLimits::default()
    };
    assert!(
        decode_response(&payload, "example.test", QueryType::A, ID, limits).is_ok(),
        "a message exactly at the limit is within bounds"
    );

    let mut frame = u16::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    assert!(
        decode_tcp_frame(&frame, "example.test", QueryType::A, ID, limits).is_ok(),
        "a frame declaring exactly the limit is within bounds"
    );

    match decode(&payload[..12]) {
        Err(Error::Decode(source)) => assert!(
            !matches!(
                source,
                packetcraftr_core::protocol::application::dns::Error::MessageTooShort { .. }
            ),
            "a header-length message passes the bounds check and fails on its question"
        ),
        other => panic!("expected a decode failure past the header, found {other:?}"),
    }
}

#[test]
fn canonical_name_at_the_exact_wire_limit_is_accepted() {
    let at_limit = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(
        canonical_query_name(&at_limit).unwrap(),
        format!("{at_limit}.")
    );
}

#[test]
fn classifications_delegate_sources_and_separate_query_faults() {
    use packetcraftr_core::error::Classified;

    let encode_source = packetcraftr_core::codec::Error::LengthOverflow {
        protocol: packetcraftr_core::layer::Id::new("dns"),
    };
    let expected = encode_source.classification();
    assert_eq!(Error::Encode(encode_source).classification(), expected);

    let decode_source = packetcraftr_core::protocol::application::dns::Error::MessageTooLarge {
        actual: 70000,
        maximum: 65535,
    };
    let expected = decode_source.classification();
    assert_eq!(Error::Decode(decode_source).classification(), expected);

    assert_eq!(
        Error::InvalidName {
            message: "x".into()
        }
        .classification()
        .code,
        "packet.dns_query"
    );
    assert_eq!(Error::NameTooLong.classification().code, "packet.dns_query");
    assert_eq!(Error::NotResponse.classification().code, "packet.dns");
}
