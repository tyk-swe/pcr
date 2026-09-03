// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr::dns::{
    self, MessageLimits as Limits, Name, QueryType, Record, RecordValue, Section, WireError,
};

const ID: u16 = 0x4a5b;
const RESPONSE: u16 = 0x8000;
const AUTHORITATIVE: u16 = 0x0400;
const TRUNCATED: u16 = 0x0200;
const RECURSION_DESIRED: u16 = 0x0100;
const RECURSION_AVAILABLE: u16 = 0x0080;
const AUTHENTICATED_DATA: u16 = 0x0020;
const CHECKING_DISABLED: u16 = 0x0010;

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

fn opt_record() -> WireRecord {
    WireRecord {
        owner: name("."),
        type_code: 41,
        class: 1_232,
        ttl: 0,
        rdata: Vec::new(),
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

fn decode(message: &[u8], query_name: &str, query_type: QueryType) -> dns::ValidatedResponse {
    dns::decode_response(message, query_name, query_type, ID, Limits::default())
        .expect("fixture response must decode")
}

#[test]
fn public_decode_functions_share_their_contract() {
    type Decode =
        fn(&[u8], &str, QueryType, u16, Limits) -> Result<dns::ValidatedResponse, WireError>;

    let _: Decode = dns::decode_response;
    let _: Decode = dns::decode_tcp_frame;
}

#[test]
fn query_encoder_canonicalizes_names_flags_and_all_type_codes() {
    let cases = [
        (QueryType::A, 1, "a"),
        (QueryType::Ns, 2, "ns"),
        (QueryType::Cname, 5, "cname"),
        (QueryType::Soa, 6, "soa"),
        (QueryType::Ptr, 12, "ptr"),
        (QueryType::Mx, 15, "mx"),
        (QueryType::Txt, 16, "txt"),
        (QueryType::Aaaa, 28, "aaaa"),
        (QueryType::Srv, 33, "srv"),
        (QueryType::Any, 255, "any"),
    ];
    for (query_type, code, label) in cases {
        assert_eq!(query_type.code(), code);
        assert_eq!(query_type.as_str(), label);
        assert_eq!(query_type.to_string(), label);
    }

    let recursive =
        dns::encode_query("WWW.Example.COM", QueryType::A, ID, true).expect("canonical query");
    assert_eq!(&recursive[..2], &ID.to_be_bytes());
    assert_eq!(&recursive[2..4], &RECURSION_DESIRED.to_be_bytes());
    assert_eq!(&recursive[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&recursive[12..29], &name("www.example.com."));
    assert_eq!(&recursive[29..], &[0, 1, 0, 1]);

    let root = dns::encode_query(".", QueryType::Any, ID, false).expect("root query");
    assert_eq!(&root[12..], &[0, 0, 255, 0, 1]);
}

#[test]
fn names_are_lossless_case_insensitive_and_safely_presented() {
    let upper = Name::from_labels([Bytes::from_static(b"WWW"), Bytes::from_static(b"Example")])
        .expect("wire name");
    let lower = Name::from_labels([Bytes::from_static(b"www"), Bytes::from_static(b"example")])
        .expect("wire name");
    assert_eq!(upper, lower);
    assert_eq!(upper.labels().len(), 2);
    assert_eq!(upper.to_string(), "WWW.Example.");

    let escaped = Name::from_labels([Bytes::from_static(b"a.b\\\0")]).expect("octet label");
    assert_eq!(escaped.to_string(), "a\\046b\\092\\000.");
    type Expected = fn(&WireError) -> bool;
    let cases: [(Vec<Bytes>, &str, Expected); 3] = [
        (vec![Bytes::new()], "empty label", |error| {
            matches!(error, WireError::InvalidName { .. })
        }),
        (
            vec![Bytes::from(vec![b'a'; 64])],
            "64-octet label",
            |error| matches!(error, WireError::InvalidName { .. }),
        ),
        (
            (0..4).map(|_| Bytes::from(vec![b'a'; 63])).collect(),
            "256-octet name",
            |error| matches!(error, WireError::NameTooLong),
        ),
    ];
    for (labels, description, is_expected) in cases {
        let error = Name::from_labels(labels).expect_err(description);
        assert!(is_expected(&error), "{description}: {error:?}");
    }
    assert_eq!(Section::Answer.to_string(), "answer");
    assert_eq!(Section::Authority.to_string(), "authority");
    assert_eq!(Section::Additional.to_string(), "additional");
}

#[test]
fn canonical_name_validation_rejects_empty_oversize_and_non_wire_characters() {
    assert_eq!(
        dns::canonical_query_name("*.SRV_example.test."),
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
        assert!(dns::canonical_query_name(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn basic_response_retains_header_flags_and_a_record() {
    let message = response(
        "www.example.com.",
        QueryType::A,
        RESPONSE
            | AUTHORITATIVE
            | RECURSION_DESIRED
            | RECURSION_AVAILABLE
            | AUTHENTICATED_DATA
            | CHECKING_DISABLED,
        &[record(1, vec![192, 0, 2, 10])],
        &[],
        &[],
    );
    let decoded = decode(&message, "WWW.Example.COM", QueryType::A);
    let owner = Name::from_labels([
        Bytes::from_static(b"www"),
        Bytes::from_static(b"example"),
        Bytes::from_static(b"com"),
    ])
    .expect("fixture owner");
    assert_eq!(
        decoded,
        dns::ValidatedResponse {
            metadata: dns::ResponseMetadata {
                response_code: 0,
                edns: None,
                authoritative: true,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                authenticated_data: true,
                checking_disabled: true,
                rejected_record_count: 0,
            },
            answers: vec![Record {
                owner,
                class: 1,
                ttl: 300,
                value: RecordValue::A(Ipv4Addr::new(192, 0, 2, 10)),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: Vec::new(),
        }
    );
    assert_eq!(decoded.response_code_name(), "no_error");
}

#[test]
fn truncated_response_stops_after_the_complete_question() {
    let mut message = response(
        "example.test.",
        QueryType::A,
        RESPONSE | TRUNCATED | AUTHORITATIVE,
        &[record(1, vec![192, 0, 2, 1])],
        &[],
        &[],
    );
    message.truncate(name("example.test.").len() + 16);
    let decoded = dns::decode_response(
        &message,
        "example.test",
        QueryType::A,
        ID,
        Limits {
            max_records: 0,
            ..Limits::default()
        },
    )
    .expect("truncation returns before record limits and partial RDATA");
    assert_eq!(
        decoded,
        dns::ValidatedResponse {
            metadata: dns::ResponseMetadata {
                response_code: 0,
                edns: None,
                authoritative: true,
                truncated: true,
                recursion_desired: false,
                recursion_available: false,
                authenticated_data: false,
                checking_disabled: false,
                rejected_record_count: 0,
            },
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: Vec::new(),
        }
    );
}

#[test]
fn decoder_error_precedence_is_stable() {
    assert!(matches!(
        dns::decode_response(&[], "", QueryType::A, ID, Limits::default()),
        Err(WireError::InvalidName { .. })
    ));

    let base = response("example.test.", QueryType::A, RESPONSE, &[], &[], &[]);
    let mut combined = base.clone();
    combined[0..2].copy_from_slice(&(ID + 1).to_be_bytes());
    combined[2..4].copy_from_slice(&((1_u16 << 11) | 0x40).to_be_bytes());
    combined[4..6].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        dns::decode_response(
            &combined,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::NotResponse)
    ));

    combined[2..4].copy_from_slice(&(RESPONSE | (1 << 11) | 0x40).to_be_bytes());
    assert!(matches!(
        dns::decode_response(
            &combined,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::UnsupportedOpcode { opcode: 1 })
    ));

    combined[2..4].copy_from_slice(&(RESPONSE | 0x40).to_be_bytes());
    assert!(matches!(
        dns::decode_response(
            &combined,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::ReservedHeaderBits)
    ));

    combined[2..4].copy_from_slice(&RESPONSE.to_be_bytes());
    assert!(matches!(
        dns::decode_response(
            &combined,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::TransactionIdMismatch { .. })
    ));

    let mut truncated_wrong_question = base;
    truncated_wrong_question[2..4].copy_from_slice(&(RESPONSE | TRUNCATED).to_be_bytes());
    truncated_wrong_question[13] = b'x';
    assert!(matches!(
        dns::decode_response(
            &truncated_wrong_question,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::QuestionNameMismatch { .. })
    ));

    let opt = WireRecord {
        owner: name("."),
        type_code: 41,
        class: 1_232,
        ttl: 0,
        rdata: Vec::new(),
    };
    let mut misplaced_with_trailing =
        response("example.test.", QueryType::A, RESPONSE, &[opt], &[], &[]);
    misplaced_with_trailing.push(0xff);
    assert!(matches!(
        dns::decode_response(
            &misplaced_with_trailing,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::TrailingBytes { remaining: 1 })
    ));
}

#[test]
fn header_and_question_validation_fail_closed() {
    assert!(matches!(
        dns::decode_response(
            &[0; 11],
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::MessageTooShort { .. })
    ));

    let base = response("example.test.", QueryType::A, RESPONSE, &[], &[], &[]);
    let limits = Limits {
        max_message_bytes: base.len() - 1,
        ..Limits::default()
    };
    assert!(matches!(
        dns::decode_response(&base, "example.test", QueryType::A, ID, limits),
        Err(WireError::MessageTooLarge { .. })
    ));

    let mut mutations = Vec::new();
    let mut query = base.clone();
    query[2..4].copy_from_slice(&0_u16.to_be_bytes());
    mutations.push((query, "not_response"));
    let mut opcode = base.clone();
    opcode[2..4].copy_from_slice(&(RESPONSE | (1 << 11)).to_be_bytes());
    mutations.push((opcode, "opcode"));
    let mut reserved = base.clone();
    reserved[2..4].copy_from_slice(&(RESPONSE | 0x40).to_be_bytes());
    mutations.push((reserved, "reserved"));
    let mut id = base.clone();
    id[0..2].copy_from_slice(&(ID + 1).to_be_bytes());
    mutations.push((id, "id"));
    let mut questions = base.clone();
    questions[4..6].copy_from_slice(&2_u16.to_be_bytes());
    mutations.push((questions, "questions"));
    let mut qname = base.clone();
    qname[13] = b'x';
    mutations.push((qname, "qname"));
    let mut qtype = base.clone();
    let type_offset = qtype.len() - 4;
    qtype[type_offset..type_offset + 2].copy_from_slice(&QueryType::Aaaa.code().to_be_bytes());
    mutations.push((qtype, "qtype"));
    let mut qclass = base;
    let class_offset = qclass.len() - 2;
    qclass[class_offset..].copy_from_slice(&3_u16.to_be_bytes());
    mutations.push((qclass, "qclass"));

    for (message, case) in mutations {
        assert!(
            dns::decode_response(
                &message,
                "example.test",
                QueryType::A,
                ID,
                Limits::default()
            )
            .is_err(),
            "{case}"
        );
    }
}

#[test]
fn unrelated_question_errors_are_distinct_from_malformed_messages() {
    let base = response("example.test.", QueryType::A, RESPONSE, &[], &[], &[]);
    let errors = [
        dns::decode_response(&base, "other.test", QueryType::A, ID, Limits::default())
            .expect_err("question name mismatch"),
        dns::decode_response(
            &base,
            "example.test",
            QueryType::Aaaa,
            ID,
            Limits::default(),
        )
        .expect_err("question type mismatch"),
        dns::decode_response(
            &base,
            "example.test",
            QueryType::A,
            ID + 1,
            Limits::default(),
        )
        .expect_err("transaction mismatch"),
    ];
    for error in errors {
        assert!(error.is_unrelated());
    }
    assert!(!WireError::NotResponse.is_unrelated());
}

#[test]
fn decoder_supports_every_modeled_rdata_shape() {
    let mut soa = name("ns.example.test.");
    soa.extend_from_slice(&name("hostmaster.example.test."));
    for value in [1_u32, 2, 3, 4, 5] {
        soa.extend_from_slice(&value.to_be_bytes());
    }
    let mut mx = 10_u16.to_be_bytes().to_vec();
    mx.extend_from_slice(&name("mail.example.test."));
    let mut srv = Vec::new();
    for value in [1_u16, 2, 443] {
        srv.extend_from_slice(&value.to_be_bytes());
    }
    srv.extend_from_slice(&name("service.example.test."));
    let records = vec![
        record(1, vec![192, 0, 2, 1]),
        record(2, name("ns.example.test.")),
        record(5, name("alias.example.test.")),
        record(6, soa),
        record(12, name("ptr.example.test.")),
        record(15, mx),
        record(16, vec![3, b'a', b'b', b'c', 0, 2, b'd', b'e']),
        record(
            28,
            "2001:db8::1"
                .parse::<Ipv6Addr>()
                .expect("IPv6")
                .octets()
                .to_vec(),
        ),
        record(33, srv),
        record(65_000, vec![9, 8, 7]),
    ];
    let message = response(
        "example.test.",
        QueryType::Any,
        RESPONSE,
        &records,
        &[],
        &[],
    );
    let decoded = decode(&message, "example.test", QueryType::Any);
    assert_eq!(decoded.answers.len(), records.len());
    let names = decoded
        .answers
        .iter()
        .map(|record| record.value.type_name())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "a", "ns", "cname", "soa", "ptr", "mx", "txt", "aaaa", "srv", "unknown"
        ]
    );
    assert_eq!(decoded.answers[0].value.type_code(), 1);
    assert_eq!(decoded.answers[9].value.type_code(), 65_000);
    assert!(matches!(
        &decoded.answers[6].value,
        RecordValue::Txt(strings)
            if strings == &[Bytes::from_static(b"abc"), Bytes::new(), Bytes::from_static(b"de")]
    ));
    assert!(matches!(
        &decoded.answers[9].value,
        RecordValue::Unknown { rdata, .. } if rdata.as_ref() == [9, 8, 7]
    ));
}

#[test]
fn edns_metadata_extends_response_code_and_retains_options() {
    let opt = WireRecord {
        owner: name("."),
        type_code: 41,
        class: 1_232,
        ttl: (1_u32 << 24) | 0x8000,
        rdata: vec![0, 10, 0, 2, 0xaa, 0xbb],
    };
    let message = response(
        "example.test.",
        QueryType::A,
        RESPONSE | 2,
        &[record(1, vec![192, 0, 2, 1])],
        &[],
        &[opt],
    );
    let decoded = decode(&message, "example.test", QueryType::A);
    assert_eq!(decoded.metadata.response_code, 18);
    assert_eq!(decoded.response_code_name(), "bad_time");
    let edns = decoded.metadata.edns.expect("EDNS metadata");
    assert_eq!(edns.udp_payload_size, 1_232);
    assert_eq!(edns.extended_response_code, 1);
    assert_eq!(edns.version, 0);
    assert!(edns.dnssec_ok);
    assert_eq!(edns.flags, 0x8000);
    assert_eq!(edns.options.len(), 1);
    assert_eq!(edns.options[0].code, 10);
    assert_eq!(edns.options[0].data.as_ref(), [0xaa, 0xbb]);
    assert!(decoded.additionals.is_empty());
}

#[test]
fn duplicate_edns_records_are_rejected() {
    let opt = opt_record();
    let duplicate = response(
        "example.test.",
        QueryType::A,
        RESPONSE,
        &[],
        &[],
        &[opt.clone(), opt.clone()],
    );
    assert!(matches!(
        dns::decode_response(
            &duplicate,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::DuplicateEdns)
    ));
}

#[test]
fn misplaced_edns_records_are_rejected() {
    let opt = opt_record();
    let answer_opt = response(
        "example.test.",
        QueryType::A,
        RESPONSE,
        std::slice::from_ref(&opt),
        &[],
        &[],
    );
    assert!(matches!(
        dns::decode_response(
            &answer_opt,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::InvalidEdns { .. })
    ));

    let mut non_root = opt;
    non_root.owner = compressed_owner();
    let non_root = response(
        "example.test.",
        QueryType::A,
        RESPONSE,
        &[],
        &[],
        &[non_root],
    );
    assert!(matches!(
        dns::decode_response(
            &non_root,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::InvalidEdns { .. })
    ));
}

#[test]
fn unsupported_edns_versions_and_invalid_option_lengths_are_rejected() {
    let mut version = opt_record();
    version.ttl = 1 << 16;
    let version = response(
        "example.test.",
        QueryType::A,
        RESPONSE,
        &[],
        &[],
        &[version],
    );
    assert!(matches!(
        dns::decode_response(
            &version,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::UnsupportedEdnsVersion { version: 1 })
    ));

    let mut bad_option = opt_record();
    bad_option.rdata = vec![0, 1, 0, 2, 0xff];
    let bad_option = response(
        "example.test.",
        QueryType::A,
        RESPONSE,
        &[],
        &[],
        &[bad_option],
    );
    assert!(matches!(
        dns::decode_response(
            &bad_option,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::InvalidEdns { .. })
    ));
}

#[test]
fn relevance_filter_follows_cname_authority_and_glue_references() {
    let alias = name("alias.example.test.");
    let answers = [
        record(5, alias.clone()),
        WireRecord {
            owner: alias,
            type_code: 1,
            class: 1,
            ttl: 60,
            rdata: vec![192, 0, 2, 5],
        },
        WireRecord {
            owner: name("unrelated.test."),
            type_code: 1,
            class: 1,
            ttl: 60,
            rdata: vec![192, 0, 2, 9],
        },
    ];
    let authority = WireRecord {
        owner: name("example.test."),
        type_code: 2,
        class: 1,
        ttl: 60,
        rdata: name("ns.example.test."),
    };
    let additionals = [
        WireRecord {
            owner: name("ns.example.test."),
            type_code: 1,
            class: 1,
            ttl: 60,
            rdata: vec![192, 0, 2, 53],
        },
        WireRecord {
            owner: name("ambient.test."),
            type_code: 1,
            class: 3,
            ttl: 60,
            rdata: vec![192, 0, 2, 54],
        },
    ];
    let message = response(
        "www.example.test.",
        QueryType::A,
        RESPONSE,
        &answers,
        &[authority],
        &additionals,
    );
    let limits = Limits {
        max_rejected_records: 1,
        ..Limits::default()
    };
    let decoded = dns::decode_response(&message, "www.example.test", QueryType::A, ID, limits)
        .expect("relevance-filtered response");
    assert_eq!(decoded.answers.len(), 2);
    assert_eq!(decoded.authorities.len(), 1);
    assert_eq!(decoded.additionals.len(), 1);
    assert_eq!(decoded.metadata.rejected_record_count, 2);
    assert_eq!(decoded.rejected_records.len(), 1);
    assert_eq!(decoded.rejected_records[0].section, Section::Answer);
    assert!(decoded.rejected_records[0].reason.contains("unrelated"));
}

#[test]
fn record_limits_trailing_bytes_and_malformed_rdata_are_rejected() {
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
        dns::decode_response(&base, "example.test", QueryType::A, ID, limits),
        Err(WireError::RecordLimit {
            actual: 1,
            limit: 0
        })
    ));

    let mut trailing = base;
    trailing.push(0xff);
    assert!(matches!(
        dns::decode_response(
            &trailing,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::TrailingBytes { remaining: 1 })
    ));

    for (query_type, malformed) in [
        (QueryType::A, record(1, vec![1, 2, 3])),
        (QueryType::Aaaa, record(28, vec![0; 15])),
        (QueryType::Mx, record(15, vec![0, 1])),
        (QueryType::Srv, record(33, vec![0; 6])),
        (QueryType::Txt, record(16, vec![3, b'a'])),
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
            dns::decode_response(&message, "example.test", query_type, ID, Limits::default()),
            Err(WireError::InvalidRdata { .. })
        ));
    }
}

#[test]
fn txt_limits_and_name_compression_safety_are_enforced() {
    let message = response(
        "example.test.",
        QueryType::Txt,
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
        dns::decode_response(&message, "example.test", QueryType::Txt, ID, string_limit),
        Err(WireError::TxtStringLimit { limit: 1 })
    ));
    let byte_limit = Limits {
        max_txt_bytes: 1,
        ..Limits::default()
    };
    assert!(matches!(
        dns::decode_response(&message, "example.test", QueryType::Txt, ID, byte_limit),
        Err(WireError::TxtByteLimit { limit: 1 })
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
        dns::decode_response(
            &pointer_message,
            "example.test",
            QueryType::A,
            ID,
            pointer_limit
        ),
        Err(WireError::PointerLimit { limit: 0 })
    ));

    for (question, expected) in [
        (vec![0xc0, 0x0c], "loop"),
        (vec![0xc0, 0xff], "out_of_bounds"),
        (vec![0x40, 0], "reserved"),
    ] {
        let mut malformed = Vec::new();
        malformed.extend_from_slice(&ID.to_be_bytes());
        malformed.extend_from_slice(&RESPONSE.to_be_bytes());
        malformed.extend_from_slice(&1_u16.to_be_bytes());
        malformed.extend_from_slice(&[0; 6]);
        malformed.extend_from_slice(&question);
        malformed.extend_from_slice(&QueryType::A.code().to_be_bytes());
        malformed.extend_from_slice(&1_u16.to_be_bytes());
        assert!(
            dns::decode_response(
                &malformed,
                "example.test",
                QueryType::A,
                ID,
                Limits::default()
            )
            .is_err(),
            "{expected}"
        );
    }
}

fn tcp_frame(message: &[u8]) -> Vec<u8> {
    let mut frame = u16::try_from(message.len())
        .expect("fixture DNS response fits TCP prefix")
        .to_be_bytes()
        .to_vec();
    frame.extend_from_slice(message);
    frame
}

#[test]
fn dns_over_tcp_accepts_one_exact_complete_response() {
    let message = response("example.test.", QueryType::A, RESPONSE, &[], &[], &[]);
    let decoded = dns::decode_tcp_frame(
        &tcp_frame(&message),
        "example.test",
        QueryType::A,
        ID,
        Limits::default(),
    )
    .expect("exact DNS-over-TCP response");
    assert!(!decoded.metadata.truncated);
}

#[test]
fn dns_over_tcp_rejects_short_prefix_and_zero_length_message() {
    assert!(matches!(
        dns::decode_tcp_frame(&[0], "example.test", QueryType::A, ID, Limits::default()),
        Err(WireError::MessageTooShort { minimum: 2, .. })
    ));
    assert_eq!(
        dns::decode_tcp_frame(&[0, 0], "example.test", QueryType::A, ID, Limits::default()),
        Err(WireError::TcpFrameZeroLength)
    );
}

#[test]
fn dns_over_tcp_rejects_oversized_declaration_before_incomplete_frame() {
    let limits = Limits {
        max_message_bytes: 12,
        ..Limits::default()
    };
    assert_eq!(
        dns::decode_tcp_frame(&[0, 13], "example.test", QueryType::A, ID, limits),
        Err(WireError::MessageTooLarge {
            actual: 13,
            maximum: 12,
        })
    );
}

#[test]
fn dns_over_tcp_rejects_incomplete_and_trailing_frame_bytes() {
    let message = response("example.test.", QueryType::A, RESPONSE, &[], &[], &[]);
    let mut incomplete = tcp_frame(&message);
    let declared = message.len() + 1;
    incomplete[..2].copy_from_slice(
        &u16::try_from(declared)
            .expect("fixture DNS response fits TCP prefix")
            .to_be_bytes(),
    );
    assert_eq!(
        dns::decode_tcp_frame(
            &incomplete,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::TcpFrameLength {
            declared,
            actual: message.len(),
        })
    );

    let mut trailing = tcp_frame(&message);
    trailing.push(0xff);
    assert_eq!(
        dns::decode_tcp_frame(
            &trailing,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::TcpFrameLength {
            declared: message.len(),
            actual: message.len() + 1,
        })
    );
}

#[test]
fn dns_over_tcp_preserves_dns_malformed_trailing_and_identity_validation() {
    let malformed = tcp_frame(&[0; 11]);
    assert!(matches!(
        dns::decode_tcp_frame(
            &malformed,
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::MessageTooShort {
            actual: 11,
            minimum: 12,
        })
    ));

    let mut dns_trailing = response("example.test.", QueryType::A, RESPONSE, &[], &[], &[]);
    dns_trailing.push(0xff);
    assert_eq!(
        dns::decode_tcp_frame(
            &tcp_frame(&dns_trailing),
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::TrailingBytes { remaining: 1 })
    );

    let message = response("example.test.", QueryType::A, RESPONSE, &[], &[], &[]);
    assert!(matches!(
        dns::decode_tcp_frame(
            &tcp_frame(&message),
            "example.test",
            QueryType::A,
            ID + 1,
            Limits::default()
        ),
        Err(WireError::TransactionIdMismatch { .. })
    ));
}

#[test]
fn dns_over_tcp_rejects_a_response_that_is_still_truncated() {
    let message = response(
        "example.test.",
        QueryType::A,
        RESPONSE | TRUNCATED,
        &[],
        &[],
        &[],
    );
    assert_eq!(
        dns::decode_tcp_frame(
            &tcp_frame(&message),
            "example.test",
            QueryType::A,
            ID,
            Limits::default()
        ),
        Err(WireError::TcpResponseTruncated)
    );
}

#[test]
fn response_code_names_cover_standard_and_extended_values() {
    let expected = [
        (0, "no_error"),
        (1, "format_error"),
        (2, "server_failure"),
        (3, "name_error"),
        (4, "not_implemented"),
        (5, "refused"),
        (6, "yx_domain"),
        (7, "yx_rrset"),
        (8, "nx_rrset"),
        (9, "not_authoritative"),
        (10, "not_zone"),
        (16, "bad_version"),
        (17, "bad_key"),
        (18, "bad_time"),
        (19, "bad_mode"),
        (20, "bad_name"),
        (21, "bad_algorithm"),
        (22, "bad_truncation"),
        (23, "bad_cookie"),
        (24, "unknown"),
    ];
    for (code, name) in expected {
        assert_eq!(dns::response_code_name(code), name);
    }
}
