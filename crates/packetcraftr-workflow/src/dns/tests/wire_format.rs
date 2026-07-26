// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

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
