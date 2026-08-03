// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn query() -> Bytes {
    Bytes::from_static(&[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'W', b'w',
        b'W', 7, b'E', b'x', b'a', b'm', b'P', b'L', b'E', 0, 0, 1, 0, 1,
    ])
}

#[test]
fn parses_bounded_header_and_questions_without_losing_wire_bytes() {
    let wire = query();
    let dns = Dns::from_wire(wire.clone()).unwrap();
    assert_eq!(dns.id, 0x1234);
    assert_eq!(dns.qnames, vec!["WwW.ExamPLE."]);
    assert_eq!(dns.qtypes, vec![1]);
    assert_eq!(dns.qclasses, vec![1]);
    assert_eq!(dns.wire(), &wire);
    assert_eq!(
        dns.field("qname"),
        Some(FieldValue::List(vec![FieldValue::Text(
            "WwW.ExamPLE.".to_owned()
        )]))
    );
}

#[test]
fn rejects_forward_pointers_and_oversized_question_lists() {
    let mut forward = query().to_vec();
    forward[12] = 0xc0;
    forward[13] = 0xff;
    assert!(matches!(
        Dns::from_wire(forward),
        Err(CodecError::Invalid { .. })
    ));

    let mut many = vec![0; DNS_HEADER_LEN];
    many[4..6].copy_from_slice(&65_u16.to_be_bytes());
    assert!(matches!(
        Dns::from_wire(many),
        Err(CodecError::Invalid { .. })
    ));
}

#[test]
fn rejects_fields_that_diverge_from_retained_wire_bytes() {
    let mut dns = Dns::from_wire(query()).unwrap();
    dns.id ^= 1;

    assert!(matches!(
        dns.validate_wire_consistency(),
        Err(CodecError::Invalid { .. })
    ));
}

#[test]
fn enforces_truncation_label_name_and_pointer_bounds() {
    assert!(matches!(
        Dns::from_wire(Bytes::new()),
        Err(CodecError::Truncated { .. })
    ));

    let mut long_label = vec![0; DNS_HEADER_LEN];
    long_label[4..6].copy_from_slice(&1_u16.to_be_bytes());
    long_label.push(64);
    assert!(Dns::from_wire(long_label).is_err());

    let mut long_name = vec![0; DNS_HEADER_LEN];
    long_name[4..6].copy_from_slice(&1_u16.to_be_bytes());
    long_name.push(63);
    long_name.extend(std::iter::repeat_n(b'a', 63));
    long_name.push(63);
    long_name.extend(std::iter::repeat_n(b'b', 63));
    long_name.push(63);
    long_name.extend(std::iter::repeat_n(b'c', 63));
    long_name.push(63);
    long_name.extend(std::iter::repeat_n(b'd', 63));
    long_name.push(0);
    assert!(matches!(
        Dns::from_wire(long_name),
        Err(CodecError::Invalid { .. })
    ));

    let base = 64;
    let pointer_count = MAX_NAME_POINTERS + 1;
    let start = base + pointer_count * 2;
    let mut pointers = vec![0; start + 2];
    for index in 0..pointer_count {
        let offset = base + index * 2;
        let target = if index == 0 { 0 } else { offset - 2 };
        pointers[offset..offset + 2]
            .copy_from_slice(&(0xc000_u16 | u16::try_from(target).unwrap()).to_be_bytes());
    }
    pointers[start..start + 2]
        .copy_from_slice(&(0xc000_u16 | u16::try_from(start - 2).unwrap()).to_be_bytes());
    assert!(matches!(
        parse_name(&pointers, start),
        Err(CodecError::Invalid { .. })
    ));
}
