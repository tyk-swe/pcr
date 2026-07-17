use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use super::engine::{dns_source_port, validate_dns_execution};
use super::*;
use crate::capture::LinkType;
use crate::client::policy::Policy as TrafficPolicy;
use crate::client::target::{
    Error as TargetResolutionError, Hostname, Resolver as HostnameResolver,
};
use crate::error::Classified;
use crate::protocol::builtin::registry as default_registry;
use crate::protocol::icmp::{Icmpv4, Icmpv6};
use crate::workflow::target::Authorized;
use crate::workflow::target_adapter::PolicyAuthorizer;
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
        output.extend_from_slice(&(self.rdata.len() as u16).to_be_bytes());
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
    output.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    output.extend_from_slice(&(authorities.len() as u16).to_be_bytes());
    output.extend_from_slice(&(additionals.len() as u16).to_be_bytes());
    output.extend_from_slice(&wire_name(query_name));
    output.extend_from_slice(&query_type.code().to_be_bytes());
    output.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    for record in answers.iter().chain(authorities).chain(additionals) {
        record.encode(&mut output);
    }
    output
}

#[test]
fn query_construction_is_canonical_and_bounded() {
    let query = encode_dns_query("WWW.Example.TEST.", DnsQueryType::Aaaa, 0x5043, true)
        .expect("valid query");
    assert_eq!(
        query.as_ref(),
        &[
            0x50, 0x43, // transaction ID
            0x01, 0x00, // recursion desired
            0x00, 0x01, // one question
            0x00, 0x00, // no answers
            0x00, 0x00, // no authority records
            0x00, 0x00, // no additional records
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x04, b't',
            b'e', b's', b't', 0x00, // root label
            0x00, 0x1c, // AAAA
            0x00, 0x01, // IN
        ]
    );
    assert!(matches!(
        canonical_query_name("bad name.example"),
        Err(DnsWireError::InvalidName { .. })
    ));
    assert!(matches!(
        canonical_query_name(&format!("{}.example", "a".repeat(64))),
        Err(DnsWireError::InvalidName { .. })
    ));
    assert_eq!(dns_source_port(u16::MAX, 2), DNS_EPHEMERAL_SOURCE_PORT_BASE);
    assert_eq!(dns_source_port(DNS_EPHEMERAL_SOURCE_PORT_BASE, 2), 49_153);
    assert_eq!(dns_source_port(DNS_EPHEMERAL_SOURCE_PORT_BASE - 1, 2), 1);
}

#[test]
fn valid_response_accepts_only_question_relevant_records() {
    let answers = vec![
        FixtureRecord::in_class("www.example.test", 5, wire_name("edge.example.test")),
        FixtureRecord::in_class("edge.example.test", 1, vec![192, 0, 2, 20]),
        FixtureRecord::in_class("edge.example.test", 28, vec![0; 16]),
        FixtureRecord::in_class("attacker.evil.test", 1, vec![203, 0, 113, 9]),
    ];
    let authorities = vec![
        FixtureRecord::in_class("example.test", 2, wire_name("ns1.example.test")),
        FixtureRecord::in_class("evil.test", 2, wire_name("ns.evil.test")),
    ];
    let additionals = vec![
        FixtureRecord::in_class("ns1.example.test", 1, vec![192, 0, 2, 53]),
        FixtureRecord::in_class("unrelated.example.test", 1, vec![192, 0, 2, 99]),
    ];
    let message = fixture_response(
        7,
        DNS_FLAG_RECURSION_DESIRED | DNS_FLAG_RECURSION_AVAILABLE,
        "www.example.test",
        DnsQueryType::A,
        &answers,
        &authorities,
        &additionals,
    );
    let response = decode_dns_response(
        &message,
        "www.example.test",
        DnsQueryType::A,
        7,
        DnsLimits::default(),
    )
    .unwrap();

    assert_eq!(response.answers.len(), 2);
    assert_eq!(response.authorities.len(), 1);
    assert_eq!(response.additionals.len(), 1);
    assert_eq!(response.rejected_record_count, 4);
    assert_eq!(response.rejected_records.len(), 4);
    assert_eq!(response.rejected_records[0].section, DnsSection::Answer);
    assert!(response.recursion_available);

    let mut tcp_frame = (message.len() as u16).to_be_bytes().to_vec();
    tcp_frame.extend_from_slice(&message);
    let tcp_response = decode_dns_tcp_frame(
        &tcp_frame,
        "www.example.test",
        DnsQueryType::A,
        7,
        DnsLimits::default(),
    )
    .unwrap();
    assert_eq!(tcp_response.answers.len(), 2);
    assert_eq!(tcp_response.rejected_record_count, 4);

    let tight_limits = DnsLimits {
        max_records: 1,
        ..DnsLimits::default()
    };
    assert!(matches!(
        decode_dns_response(
            &message,
            "www.example.test",
            DnsQueryType::A,
            7,
            tight_limits,
        ),
        Err(DnsWireError::RecordLimit { .. })
    ));
}

#[test]
fn compressed_owner_and_dnssec_header_bits_are_validated_without_rejection() {
    let mut message = fixture_response(
        0x1234,
        DNS_FLAG_AUTHENTICATED_DATA | DNS_FLAG_CHECKING_DISABLED,
        "compressed.example",
        DnsQueryType::A,
        &[],
        &[],
        &[],
    );
    message[6..8].copy_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&[0xc0, 0x0c]);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    message.extend_from_slice(&30u32.to_be_bytes());
    message.extend_from_slice(&4u16.to_be_bytes());
    message.extend_from_slice(&[192, 0, 2, 1]);

    let response = decode_dns_response(
        &message,
        "compressed.example",
        DnsQueryType::A,
        0x1234,
        DnsLimits::default(),
    )
    .unwrap();
    assert_eq!(response.answers.len(), 1);
    assert!(response.authenticated_data);
    assert!(response.checking_disabled);
}

#[test]
fn txt_bytes_remain_exact_even_when_they_contain_terminal_controls() {
    let bytes = vec![b'a', 0x1b, b'[', b'3', b'1'];
    let mut txt = vec![bytes.len() as u8];
    txt.extend_from_slice(&bytes);
    let message = fixture_response(
        9,
        0,
        "txt.example",
        DnsQueryType::Txt,
        &[FixtureRecord::in_class("txt.example", 16, txt)],
        &[],
        &[],
    );
    let response = decode_dns_response(
        &message,
        "txt.example",
        DnsQueryType::Txt,
        9,
        DnsLimits::default(),
    )
    .unwrap();
    let DnsRecordValue::Txt(strings) = &response.answers[0].value else {
        panic!("expected TXT record");
    };
    assert_eq!(strings, &[Bytes::from(bytes)]);
    assert!(matches!(
        decode_dns_response(
            &message,
            "txt.example",
            DnsQueryType::Txt,
            9,
            DnsLimits {
                max_txt_bytes: 4,
                ..DnsLimits::default()
            },
        ),
        Err(DnsWireError::TxtByteLimit { limit: 4 })
    ));
}

#[test]
fn wire_names_preserve_arbitrary_label_octets_and_escape_only_for_display() {
    let cases: &[(&[u8], &str)] = &[
        (b".", "\\046."),
        (b"\0", "\\000."),
        (&[0xff], "\\255."),
        (b"\\", "\\092."),
    ];
    for (label, displayed) in cases {
        let mut target = vec![label.len() as u8];
        target.extend_from_slice(label);
        target.push(0);
        let message = fixture_response(
            10,
            0,
            "name.example",
            DnsQueryType::Cname,
            &[FixtureRecord::in_class(
                "name.example",
                DnsQueryType::Cname.code(),
                target,
            )],
            &[],
            &[],
        );
        let response = decode_dns_response(
            &message,
            "name.example",
            DnsQueryType::Cname,
            10,
            DnsLimits::default(),
        )
        .unwrap();
        let DnsRecordValue::Cname(name) = &response.answers[0].value else {
            panic!("expected CNAME");
        };
        assert_eq!(name.labels(), &[Bytes::copy_from_slice(label)]);
        assert_eq!(name.to_string(), *displayed);
    }

    let lower = DnsName::from_labels([Bytes::from_static(b"case")]).unwrap();
    let upper = DnsName::from_labels([Bytes::from_static(b"CASE")]).unwrap();
    let high = DnsName::from_labels([Bytes::from_static(&[0xc0])]).unwrap();
    let different_high = DnsName::from_labels([Bytes::from_static(&[0xe0])]).unwrap();
    assert_eq!(lower, upper);
    assert_ne!(high, different_high);
}

#[test]
fn edns_extended_response_codes_and_metadata_are_validated() {
    let opt = |extended: u8, version: u8, rdata: Vec<u8>| FixtureRecord {
        owner: vec![0],
        type_code: DNS_TYPE_OPT,
        class: 1232,
        ttl: (u32::from(extended) << 24) | (u32::from(version) << 16) | 0x8000,
        rdata,
    };
    let message = fixture_response(
        11,
        0,
        "edns.example",
        DnsQueryType::A,
        &[],
        &[],
        &[opt(1, 0, vec![0, 10, 0, 2, 0xaa, 0xbb])],
    );
    let response = decode_dns_response(
        &message,
        "edns.example",
        DnsQueryType::A,
        11,
        DnsLimits::default(),
    )
    .unwrap();
    assert_eq!(response.response_code, 16);
    assert_eq!(response.response_code_name(), "bad_version");
    let edns = response.edns.unwrap();
    assert_eq!(edns.udp_payload_size, 1232);
    assert!(edns.dnssec_ok);
    assert_eq!(edns.options[0].code, 10);
    assert_eq!(edns.options[0].data.as_ref(), [0xaa, 0xbb]);

    let mixed = fixture_response(
        12,
        2,
        "edns.example",
        DnsQueryType::A,
        &[],
        &[],
        &[opt(1, 0, Vec::new())],
    );
    assert_eq!(
        decode_dns_response(
            &mixed,
            "edns.example",
            DnsQueryType::A,
            12,
            DnsLimits::default(),
        )
        .unwrap()
        .response_code,
        18
    );

    let no_opt = fixture_response(13, 3, "edns.example", DnsQueryType::A, &[], &[], &[]);
    let response = decode_dns_response(
        &no_opt,
        "edns.example",
        DnsQueryType::A,
        13,
        DnsLimits::default(),
    )
    .unwrap();
    assert_eq!(response.response_code, 3);
    assert!(response.edns.is_none());

    let duplicate = fixture_response(
        14,
        0,
        "edns.example",
        DnsQueryType::A,
        &[],
        &[],
        &[opt(0, 0, Vec::new()), opt(0, 0, Vec::new())],
    );
    assert!(matches!(
        decode_dns_response(
            &duplicate,
            "edns.example",
            DnsQueryType::A,
            14,
            DnsLimits::default(),
        ),
        Err(DnsWireError::DuplicateEdns)
    ));

    let malformed = fixture_response(
        15,
        0,
        "edns.example",
        DnsQueryType::A,
        &[],
        &[],
        &[opt(0, 0, vec![0, 1, 0, 2, 0xff])],
    );
    assert!(matches!(
        decode_dns_response(
            &malformed,
            "edns.example",
            DnsQueryType::A,
            15,
            DnsLimits::default(),
        ),
        Err(DnsWireError::InvalidEdns { .. })
    ));

    let unsupported = fixture_response(
        16,
        0,
        "edns.example",
        DnsQueryType::A,
        &[],
        &[],
        &[opt(0, 1, Vec::new())],
    );
    assert!(matches!(
        decode_dns_response(
            &unsupported,
            "edns.example",
            DnsQueryType::A,
            16,
            DnsLimits::default(),
        ),
        Err(DnsWireError::UnsupportedEdnsVersion { version: 1 })
    ));

    let misplaced_record = opt(0, 0, Vec::new());
    let misplaced = fixture_response(
        17,
        0,
        "edns.example",
        DnsQueryType::A,
        &[misplaced_record],
        &[],
        &[],
    );
    assert!(matches!(
        decode_dns_response(
            &misplaced,
            "edns.example",
            DnsQueryType::A,
            17,
            DnsLimits::default(),
        ),
        Err(DnsWireError::InvalidEdns { .. })
    ));

    let mut non_root_record = opt(0, 0, Vec::new());
    non_root_record.owner = wire_name("not-root.example");
    let non_root = fixture_response(
        18,
        0,
        "edns.example",
        DnsQueryType::A,
        &[],
        &[],
        &[non_root_record],
    );
    assert!(matches!(
        decode_dns_response(
            &non_root,
            "edns.example",
            DnsQueryType::A,
            18,
            DnsLimits::default(),
        ),
        Err(DnsWireError::InvalidEdns { .. })
    ));
}

#[test]
fn every_published_record_shape_decodes_to_typed_bounded_data() {
    let mut mx = 10u16.to_be_bytes().to_vec();
    mx.extend_from_slice(&wire_name("mail.example"));
    let mut soa = wire_name("ns1.example");
    soa.extend_from_slice(&wire_name("hostmaster.example"));
    for value in [1u32, 2, 3, 4, 5] {
        soa.extend_from_slice(&value.to_be_bytes());
    }
    let mut srv = Vec::new();
    for value in [1u16, 2, 443] {
        srv.extend_from_slice(&value.to_be_bytes());
    }
    srv.extend_from_slice(&wire_name("service.example"));
    let records = vec![
        FixtureRecord::in_class("all.example", 1, vec![192, 0, 2, 1]),
        FixtureRecord::in_class("all.example", 28, Ipv6Addr::LOCALHOST.octets().to_vec()),
        FixtureRecord::in_class("all.example", 5, wire_name("alias.example")),
        FixtureRecord::in_class("all.example", 15, mx),
        FixtureRecord::in_class("all.example", 2, wire_name("ns1.example")),
        FixtureRecord::in_class("all.example", 12, wire_name("pointer.example")),
        FixtureRecord::in_class("all.example", 6, soa),
        FixtureRecord::in_class("all.example", 33, srv),
        FixtureRecord::in_class("all.example", 16, vec![3, b'o', b'n', b'e']),
        FixtureRecord::in_class("all.example", 99, vec![0xde, 0xad]),
    ];
    let message = fixture_response(12, 0, "all.example", DnsQueryType::Any, &records, &[], &[]);
    let response = decode_dns_response(
        &message,
        "all.example",
        DnsQueryType::Any,
        12,
        DnsLimits::default(),
    )
    .unwrap();
    assert_eq!(response.answers.len(), 10);
    assert_eq!(response.rejected_record_count, 0);
    assert_eq!(
        response
            .answers
            .iter()
            .map(|record| record.value.type_name())
            .collect::<Vec<_>>(),
        [
            "a", "aaaa", "cname", "mx", "ns", "ptr", "soa", "srv", "txt", "unknown"
        ]
    );
    let DnsRecordValue::Soa {
        serial,
        refresh,
        retry,
        expire,
        minimum,
        ..
    } = &response.answers[6].value
    else {
        panic!("expected SOA");
    };
    assert_eq!(
        [*serial, *refresh, *retry, *expire, *minimum],
        [1, 2, 3, 4, 5]
    );
    assert!(matches!(
        &response.answers[9].value,
        DnsRecordValue::Unknown { type_code: 99, rdata }
            if rdata.as_ref() == [0xde, 0xad]
    ));
}

#[test]
fn malformed_compression_and_unrelated_identity_are_typed_failures() {
    let mut looped = Vec::new();
    looped.extend_from_slice(&3u16.to_be_bytes());
    looped.extend_from_slice(&DNS_FLAG_RESPONSE.to_be_bytes());
    looped.extend_from_slice(&1u16.to_be_bytes());
    looped.extend_from_slice(&[0; 6]);
    looped.extend_from_slice(&[0xc0, 0x0c]);
    assert!(matches!(
        decode_dns_response(
            &looped,
            "loop.example",
            DnsQueryType::A,
            3,
            DnsLimits::default(),
        ),
        Err(DnsWireError::PointerLoop { .. })
    ));

    let mut forward = looped.clone();
    forward[13] = 0x0e;
    forward.push(0);
    assert!(matches!(
        decode_dns_response(
            &forward,
            "forward.example",
            DnsQueryType::A,
            3,
            DnsLimits::default(),
        ),
        Err(DnsWireError::ForwardPointer { .. })
    ));

    let valid = fixture_response(4, 0, "other.example", DnsQueryType::A, &[], &[], &[]);
    let error = decode_dns_response(
        &valid,
        "expected.example",
        DnsQueryType::A,
        4,
        DnsLimits::default(),
    )
    .unwrap_err();
    assert!(error.is_unrelated());
}

#[test]
fn truncation_never_presents_partial_records_and_tcp_length_is_exact() {
    let mut truncated = fixture_response(
        11,
        DNS_FLAG_TRUNCATED,
        "large.example",
        DnsQueryType::A,
        &[],
        &[],
        &[],
    );
    truncated[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    let response = decode_dns_response(
        &truncated,
        "large.example",
        DnsQueryType::A,
        11,
        DnsLimits::default(),
    )
    .unwrap();
    assert!(response.truncated);
    assert!(response.answers.is_empty());

    let mut frame = (truncated.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&truncated);
    assert!(
        decode_dns_tcp_frame(
            &frame,
            "large.example",
            DnsQueryType::A,
            11,
            DnsLimits::default(),
        )
        .is_ok()
    );
    frame[1] = frame[1].wrapping_add(1);
    assert!(matches!(
        decode_dns_tcp_frame(
            &frame,
            "large.example",
            DnsQueryType::A,
            11,
            DnsLimits::default(),
        ),
        Err(DnsWireError::TcpFrameLength { .. })
    ));
}

#[test]
fn correlation_requires_exact_reverse_tuple_checksum_and_dns_identity() {
    let server = Ipv4Addr::new(10, 0, 0, 53);
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let query = encode_dns_query("www.example", DnsQueryType::A, 42, true).unwrap();
    let probe = DnsProbe {
        attempt: 1,
        server_address: IpAddr::V4(server),
        server_port: 53,
        source_port: 50_000,
        transaction_id: 42,
        query_name: "www.example.".to_owned(),
        query_type: DnsQueryType::A,
        query,
    };
    let mut sent = Packet::new();
    sent.push(Ipv4 {
        source: client,
        destination: server,
        ..Ipv4::default()
    })
    .push(Udp {
        source_port: 50_000,
        destination_port: 53,
        ..Udp::default()
    })
    .push(Raw::new(Bytes::new()));
    let response_bytes = fixture_response(
        42,
        0,
        "www.example",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example",
            1,
            vec![192, 0, 2, 5],
        )],
        &[],
        &[],
    );
    let decoded = |source: Ipv4Addr, transaction_id: u16, diagnostics: Vec<Diagnostic>| {
        let mut bytes = response_bytes.clone();
        bytes[..2].copy_from_slice(&transaction_id.to_be_bytes());
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source,
                destination: client,
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 53,
                destination_port: 50_000,
                ..Udp::default()
            })
            .push(Raw::new(bytes.clone()));
        DecodedPacket {
            packet,
            original: Bytes::from(bytes.clone()),
            frame: Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap(),
            layout: crate::packet::layout::PacketLayout::default(),
            diagnostics,
        }
    };
    let registry = default_registry().unwrap();

    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(server, 42, Vec::new()),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::Response(_))
    ));
    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(server, 43, Vec::new()),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::Unrelated { .. })
    ));
    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(
                server,
                42,
                vec![Diagnostic::error("udp.checksum", "invalid checksum")],
            ),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::DecodeFailure { .. })
    ));
    assert!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(Ipv4Addr::new(10, 0, 0, 99), 42, Vec::new()),
            DnsLimits::default(),
        )
        .is_none()
    );

    let server_v6: Ipv6Addr = "fd00::53".parse().unwrap();
    let client_v6: Ipv6Addr = "fd00::2".parse().unwrap();
    let query_v6 = encode_dns_query("www.example", DnsQueryType::A, 44, true).unwrap();
    let probe_v6 = DnsProbe {
        attempt: 1,
        server_address: IpAddr::V6(server_v6),
        server_port: 53,
        source_port: 50_001,
        transaction_id: 44,
        query_name: "www.example.".to_owned(),
        query_type: DnsQueryType::A,
        query: query_v6,
    };
    let mut sent_v6 = Packet::new();
    sent_v6
        .push(Ipv6 {
            source: client_v6,
            destination: server_v6,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 50_001,
            destination_port: 53,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::new()));
    let response_v6 = fixture_response(
        44,
        0,
        "www.example",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example",
            1,
            vec![192, 0, 2, 44],
        )],
        &[],
        &[],
    );
    let mut response_packet_v6 = Packet::new();
    response_packet_v6
        .push(Ipv6 {
            source: server_v6,
            destination: client_v6,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 53,
            destination_port: 50_001,
            ..Udp::default()
        })
        .push(Raw::new(response_v6.clone()));
    let decoded_v6 = DecodedPacket {
        packet: response_packet_v6,
        original: Bytes::from(response_v6.clone()),
        frame: Frame::new(UNIX_EPOCH, LinkType::RAW, response_v6).unwrap(),
        layout: crate::packet::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    };
    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe_v6,
            &sent_v6,
            &decoded_v6,
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::Response(_))
    ));
    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &quoted_icmp_time_exceeded(&sent, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::NetworkFailure { reason })
            if reason == "ICMPv4 time exceeded before reaching the endpoint"
    ));
    let mut corrupt_icmp =
        quoted_icmp_time_exceeded(&sent, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)));
    corrupt_icmp
        .diagnostics
        .push(Diagnostic::error("icmpv4.checksum", "invalid checksum"));
    assert!(
        classify_dns_response(
            &registry,
            &probe,
            &sent,
            &corrupt_icmp,
            DnsLimits::default(),
        )
        .is_none()
    );

    assert!(matches!(
        classify_dns_response(
            &registry,
            &probe_v6,
            &sent_v6,
            &quoted_icmp_time_exceeded(&sent_v6, IpAddr::V6("fd00::fe".parse().unwrap())),
            DnsLimits::default(),
        ),
        Some(DnsResponseClassification::NetworkFailure { reason })
            if reason == "ICMPv6 time exceeded before reaching the endpoint"
    ));
}

fn quoted_icmp_time_exceeded(request: &Packet, responder: IpAddr) -> DecodedPacket {
    let udp = request.get::<Udp>().unwrap();
    let (packet, bytes) = match responder {
        IpAddr::V4(responder) => {
            let network = request.get::<Ipv4>().unwrap();
            let mut quote = vec![0_u8; 28];
            quote[0] = 0x45;
            quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
            quote[9] = 17;
            quote[12..16].copy_from_slice(&network.source.octets());
            quote[16..20].copy_from_slice(&network.destination.octets());
            quote[20..22].copy_from_slice(&udp.source_port.to_be_bytes());
            quote[22..24].copy_from_slice(&udp.destination_port.to_be_bytes());
            let mut body = vec![0_u8; 4];
            body.extend(quote);
            let mut packet = Packet::new();
            packet
                .push(Ipv4 {
                    source: responder,
                    destination: network.source,
                    ..Ipv4::default()
                })
                .push(Icmpv4 {
                    icmp_type: 11,
                    body: body.into(),
                    ..Icmpv4::default()
                });
            (packet, Bytes::from_static(&[0x45]))
        }
        IpAddr::V6(responder) => {
            let network = request.get::<Ipv6>().unwrap();
            let mut quote = vec![0_u8; 48];
            quote[0] = 0x60;
            quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
            quote[6] = 17;
            quote[8..24].copy_from_slice(&network.source.octets());
            quote[24..40].copy_from_slice(&network.destination.octets());
            quote[40..42].copy_from_slice(&udp.source_port.to_be_bytes());
            quote[42..44].copy_from_slice(&udp.destination_port.to_be_bytes());
            let mut body = vec![0_u8; 4];
            body.extend(quote);
            let mut packet = Packet::new();
            packet
                .push(Ipv6 {
                    source: responder,
                    destination: network.source,
                    ..Ipv6::default()
                })
                .push(Icmpv6 {
                    icmp_type: 3,
                    body: body.into(),
                    ..Icmpv6::default()
                });
            (packet, Bytes::from_static(&[0x60]))
        }
    };
    DecodedPacket {
        packet,
        original: bytes.clone(),
        frame: Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap(),
        layout: crate::packet::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}

struct LocalAuthorizer;

impl Authorizer for LocalAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        assert_eq!(
            target,
            &Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)))
        );
        Ok(Authorized {
            declared: target.to_string(),
            addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        _maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        assert_eq!(packets, 1);
        Ok(())
    }
}

struct PayloadExecutor {
    payload: Bytes,
}

impl DnsExecutor for PayloadExecutor {
    fn execute(&mut self, exchange: &DnsExchange) -> Result<DnsExchangeExecution, BoundaryError> {
        let sent_at = UNIX_EPOCH + Duration::from_secs(10);
        let mut response_packet = Packet::new();
        response_packet
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 53),
                destination: Ipv4Addr::UNSPECIFIED,
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: exchange.probe.server_port,
                destination_port: exchange.probe.source_port,
                ..Udp::default()
            })
            .push(Raw::new(self.payload.clone()));
        let frame = Frame::new(
            sent_at + Duration::from_millis(2),
            LinkType::RAW,
            self.payload.clone(),
        )
        .unwrap();
        Ok(DnsExchangeExecution {
            sent: exchange.probe.packet(),
            sent_evidence: Frame::new(sent_at, LinkType::RAW, exchange.probe.query.clone())
                .unwrap(),
            responses: vec![DnsMatchedResponse {
                response: DecodedPacket {
                    packet: response_packet,
                    original: self.payload.clone(),
                    frame,
                    layout: crate::packet::layout::PacketLayout::default(),
                    diagnostics: Vec::new(),
                },
                latency: Duration::from_millis(2),
            }],
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: exchange.probe.query.len() as u64,
                elapsed: Duration::from_millis(2),
                ..Stats::default()
            },
        })
    }
}

fn single_attempt_request() -> DnsRequest {
    DnsRequest {
        server: Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))),
        address_family: AddressFamily::Ipv4,
        server_port: 53,
        source_port: 50_000,
        query_name: "www.example.test".to_owned(),
        query_type: DnsQueryType::A,
        transaction_id: 77,
        recursion_desired: true,
        attempts: 1,
        timeout: Duration::from_millis(10),
        queries_per_second: None,
        limits: DnsLimits::default(),
    }
}

#[test]
fn workflow_outcomes_distinguish_valid_truncated_unrelated_and_decode_failure() {
    let valid = fixture_response(
        77,
        0,
        "www.example.test",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example.test",
            1,
            vec![192, 0, 2, 10],
        )],
        &[],
        &[],
    );
    let truncated = fixture_response(
        77,
        DNS_FLAG_TRUNCATED,
        "www.example.test",
        DnsQueryType::A,
        &[],
        &[],
        &[],
    );
    let unrelated = fixture_response(78, 0, "www.example.test", DnsQueryType::A, &[], &[], &[]);
    for (payload, outcome, status) in [
        (
            Bytes::from(valid),
            DnsOutcome::Response,
            DnsAttemptStatus::Response,
        ),
        (
            Bytes::from(truncated),
            DnsOutcome::Truncated,
            DnsAttemptStatus::Truncated,
        ),
        (
            Bytes::from(unrelated),
            DnsOutcome::Unrelated,
            DnsAttemptStatus::Unrelated,
        ),
        (
            Bytes::from_static(b"malformed"),
            DnsOutcome::DecodeFailure,
            DnsAttemptStatus::DecodeFailure,
        ),
    ] {
        let result = dns(
            &single_attempt_request(),
            &mut LocalAuthorizer,
            &default_registry().unwrap(),
            &mut PayloadExecutor { payload },
            &mut NoopClock,
        )
        .unwrap();
        assert_eq!(result.outcome, outcome);
        assert_eq!(result.attempts[0].status, status);
        assert!(result.attempts[0].response.is_some());
    }
}

#[test]
fn unsolicited_dns_response_after_the_deadline_remains_a_timeout() {
    struct LateUnsolicitedExecutor {
        payload: Bytes,
    }

    impl DnsExecutor for LateUnsolicitedExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, BoundaryError> {
            let mut execution = PayloadExecutor {
                payload: self.payload.clone(),
            }
            .execute(exchange)?;
            let mut response = execution.responses.remove(0).response;
            response.frame.timestamp =
                execution.sent_evidence.timestamp + exchange.timeout + Duration::from_millis(1);
            execution.unsolicited.push(response);
            Ok(execution)
        }
    }

    let payload = fixture_response(
        77,
        0,
        "www.example.test",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example.test",
            1,
            vec![192, 0, 2, 10],
        )],
        &[],
        &[],
    );
    let result = dns(
        &single_attempt_request(),
        &mut LocalAuthorizer,
        &default_registry().unwrap(),
        &mut LateUnsolicitedExecutor {
            payload: Bytes::from(payload),
        },
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.outcome, DnsOutcome::Timeout);
    assert_eq!(result.attempts[0].status, DnsAttemptStatus::Timeout);
}

#[test]
fn matched_response_deadline_uses_monotonic_latency_despite_wall_clock_skew() {
    struct PreSendMatchedExecutor {
        payload: Bytes,
    }

    impl DnsExecutor for PreSendMatchedExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, BoundaryError> {
            let mut execution = PayloadExecutor {
                payload: self.payload.clone(),
            }
            .execute(exchange)?;
            execution.responses[0].response.frame.timestamp = execution
                .sent_evidence
                .timestamp
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            Ok(execution)
        }
    }

    let payload = fixture_response(
        77,
        0,
        "www.example.test",
        DnsQueryType::A,
        &[FixtureRecord::in_class(
            "www.example.test",
            1,
            vec![192, 0, 2, 10],
        )],
        &[],
        &[],
    );
    let result = dns(
        &single_attempt_request(),
        &mut LocalAuthorizer,
        &default_registry().unwrap(),
        &mut PreSendMatchedExecutor {
            payload: Bytes::from(payload),
        },
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.outcome, DnsOutcome::Response);
    assert!(result.attempts[0].received_at.unwrap() < result.attempts[0].sent_at);
}

struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone)]
struct ScriptedResolver {
    calls: Arc<AtomicUsize>,
    answers: Arc<Mutex<VecDeque<Vec<IpAddr>>>>,
}

impl ScriptedResolver {
    fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Arc::new(Mutex::new(answers.into_iter().collect())),
        }
    }
}

impl HostnameResolver for ScriptedResolver {
    fn resolve(
        &self,
        hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| TargetResolutionError::NoAddresses {
                hostname: hostname.to_string(),
            })
    }
}

#[derive(Default)]
struct TimeoutExecutor {
    calls: usize,
    addresses: Vec<IpAddr>,
}

impl DnsExecutor for TimeoutExecutor {
    fn execute(&mut self, exchange: &DnsExchange) -> Result<DnsExchangeExecution, BoundaryError> {
        self.calls += 1;
        self.addresses.push(exchange.probe.server_address);
        Ok(DnsExchangeExecution {
            sent: exchange.probe.packet(),
            sent_evidence: Frame::new(
                UNIX_EPOCH + Duration::from_secs(u64::from(exchange.probe.attempt)),
                LinkType::RAW,
                exchange.probe.query.clone(),
            )
            .unwrap(),
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: exchange.probe.query.len() as u64,
                ..Stats::default()
            },
        })
    }
}

#[test]
fn executor_cannot_underreport_exact_dns_wire_bytes() {
    let query = encode_dns_query("www.example.test", DnsQueryType::A, 77, true).unwrap();
    let probe = DnsProbe {
        attempt: 1,
        server_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)),
        server_port: 53,
        source_port: 50_000,
        transaction_id: 77,
        query_name: "www.example.test.".to_owned(),
        query_type: DnsQueryType::A,
        query,
    };
    let mut execution = TimeoutExecutor::default()
        .execute(&DnsExchange {
            probe: probe.clone(),
            timeout: Duration::from_millis(10),
            max_responses: 1,
        })
        .unwrap();
    execution.stats.bytes = 0;

    assert!(matches!(
        validate_dns_execution(
            &probe,
            &execution,
            DnsLimits::default(),
            Duration::from_millis(10),
        ),
        Err(DnsError::InvalidEvidence { attempt: 1, .. })
    ));
}

fn private_policy() -> TrafficPolicy {
    TrafficPolicy {
        allow_public_destinations: false,
        allow_hostname_resolution: false,
        max_packets_per_operation: 32,
        max_bytes_per_operation: 1_000_000,
        ..TrafficPolicy::default()
    }
}

fn retry_request() -> DnsRequest {
    DnsRequest {
        server: Target::Hostname("resolver.example".to_owned()),
        address_family: AddressFamily::Any,
        server_port: 53,
        source_port: 50_000,
        query_name: "www.example.test".to_owned(),
        query_type: DnsQueryType::A,
        transaction_id: 0x5043,
        recursion_desired: true,
        attempts: 2,
        timeout: Duration::from_millis(10),
        queries_per_second: None,
        limits: DnsLimits::default(),
    }
}

#[test]
fn hostname_intent_is_denied_before_resolver_or_executor_side_effects() {
    let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]]);
    let policy = private_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let error = dns(
        &retry_request(),
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.hostname_resolution");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls, 0);
}

#[test]
fn every_mixed_answer_is_authorized_before_family_selection() {
    let resolver = ScriptedResolver::new([vec![
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    ]]);
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let mut request = retry_request();
    request.address_family = AddressFamily::Ipv6;
    request.attempts = 1;
    let error = dns(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
    assert!(error.to_string().contains("8.8.8.8"));
    assert_eq!(executor.calls, 0);
}

#[test]
fn every_retry_reresolves_and_reauthorizes_rebinding_before_probe_construction() {
    let resolver = ScriptedResolver::new([
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
        vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
    ]);
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let error = dns(
        &retry_request(),
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor.calls, 1);
    assert_eq!(
        executor.addresses,
        [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]
    );
}

#[test]
fn complete_operation_budget_precedes_resolution_and_queries() {
    let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]]);
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    policy.max_packets_per_operation = 1;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::default();
    let error = dns(
        &retry_request(),
        &mut authorizer,
        &default_registry().unwrap(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.packet_limit");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls, 0);
}

#[test]
fn aggregate_duration_is_rejected_before_operation_authorization() {
    struct CountingAuthorizer {
        operation_calls: usize,
    }

    impl Authorizer for CountingAuthorizer {
        fn resolve_and_authorize(&mut self, _target: &Target) -> Result<Authorized, BoundaryError> {
            panic!("duration validation must precede resolution")
        }

        fn authorize_operation(
            &mut self,
            _packets: u64,
            _maximum_wire_bytes: u64,
        ) -> Result<(), BoundaryError> {
            self.operation_calls += 1;
            Ok(())
        }
    }

    let mut request = single_attempt_request();
    request.attempts = 2;
    request.timeout = Duration::from_millis(10);
    request.limits.max_duration = Duration::from_millis(1);
    let mut authorizer = CountingAuthorizer { operation_calls: 0 };
    let error = dns(
        &request,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut TimeoutExecutor::default(),
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, DnsError::DurationLimit { .. }));
    assert_eq!(authorizer.operation_calls, 0);
}
