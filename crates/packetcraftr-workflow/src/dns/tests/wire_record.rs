// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

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
