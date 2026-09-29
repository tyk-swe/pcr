// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::decoded::{context, tunnelled};
use packetcraftr_core::{
    filter::{Filter, Limits},
    protocol::builtin,
};
#[test]
fn unquoted_dotted_words_remain_text_literals() {
    for (protocol, bytes, source) in [
        (
            "raw",
            b"example.test".as_slice(),
            "raw.bytes == example.test",
        ),
        (
            "http",
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
            "http.version == HTTP/1.1",
        ),
    ] {
        let registry = common::packets::rooted_registry(protocol);
        let frame = packetcraftr_core::frame::Frame::new(
            std::time::UNIX_EPOCH,
            common::packets::ROOT_LINK_TYPE,
            bytes.to_vec(),
        )
        .unwrap();
        let packet = packetcraftr_core::decode::Dissector::new(registry.clone())
            .decode(frame, Default::default())
            .unwrap();
        assert!(
            Filter::compile(source, &registry, Limits::default())
                .unwrap()
                .matches(&context(&packet))
                .unwrap(),
            "{source}"
        );
    }
}
#[test]
fn advanced_filters_use_byte_functions_and_explicit_repeated_value_semantics() {
    let packet = tunnelled();
    let registry = builtin::registry();
    for (source, expected) in [
        (r#"raw.bytes matches "^GET /[a-z]+ HTTP/1[.]1$""#, true),
        (r#"raw.bytes matches "^POST""#, false),
        ("len(raw.bytes) == 19", true),
        ("count(udp.source_port) == 2", true),
        (r#"lower(raw.bytes) == "get /index http/1.1""#, true),
        (r#"upper(raw.bytes) == "GET /INDEX HTTP/1.1""#, true),
        (r#"starts_with(raw.bytes, "GET ")"#, true),
        (r#"ends_with(lower(raw.bytes), "http/1.1")"#, true),
        ("udp.source_port == udp.destination_port", false),
        ("ipv4.source != ipv4.destination", true),
        ("any udp.destination_port == 9999", true),
        ("all udp.destination_port == 9999", false),
        ("all udp.source_port > 1000", true),
        ("all ipv4.more_fragments == 0", true),
        ("any ethernet.source[0] == 6", true),
        ("any ethernet.source == 06:07:08:09:0a:0b", true),
        ("all tcp.source_port != 0", false),
        ("all udp.source_port == udp.source_port", false),
        ("any udp.source_port == udp.source_port", true),
    ] {
        let filter = Filter::compile(source, &registry, Limits::default())
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        assert_eq!(
            filter.matches(&context(&packet)).unwrap(),
            expected,
            "{source}"
        );
    }
}
#[test]
fn both_comparison_operands_record_requirements_and_reject_incompatible_types() {
    let registry = builtin::registry();
    let filter = Filter::compile(
        "frame.number == tcp.stream || frame.number == frame.time_epoch",
        &registry,
        Limits::default(),
    )
    .unwrap();
    assert!(filter.requirements().tcp_stream);
    assert!(filter.requirements().timestamp);
    let aliases = builtin::registry_with(|builder| {
        for (path, field) in [("_left", "source_port"), ("_right", "destination_port")] {
            builder.bind_filter_field(
                path,
                packetcraftr_core::registry::FilterFieldBinding::Direct {
                    protocol: "udp".into(),
                    field,
                },
            )?;
        }
        Ok(())
    })
    .unwrap();
    assert!(
        !Filter::compile("_left == _right", &aliases, Limits::default())
            .unwrap()
            .matches(&context(&tunnelled()))
            .unwrap()
    );
    for source in [
        r#"tcp.source_port matches "x""#,
        r#"lower(tcp.source_port) == "x""#,
        "ipv4.source == udp.source_port",
        "all ipv4.source > 192.0.2.0/24",
        r#"raw.bytes matches "[""#,
    ] {
        assert!(
            Filter::compile(source, &registry, Limits::default()).is_err(),
            "{source}"
        );
    }
    let source = format!("raw.bytes matches \"{}\"", "a".repeat(8193));
    assert!(Filter::compile(&source, &registry, Limits::default()).is_err());
    assert!(
        Filter::compile(
            r#"raw.bytes matches "a{100000000}""#,
            &registry,
            Limits::default()
        )
        .is_err()
    );
}

#[test]
fn byte_regexes_accept_invalid_utf8_and_case_conversion_preserves_non_ascii_octets() {
    let registry = common::packets::rooted_registry("raw");
    let frame = packetcraftr_core::frame::Frame::new(
        std::time::UNIX_EPOCH,
        common::packets::ROOT_LINK_TYPE,
        vec![0xff, 0xc3, 0x9f, b'A', b'b'],
    )
    .unwrap();
    let packet = packetcraftr_core::decode::Dissector::new(registry.clone())
        .decode(frame, Default::default())
        .unwrap();
    let view = context(&packet);
    assert!(
        Filter::compile(
            r#"raw.bytes matches "[\\x80-\\xFF]""#,
            &registry,
            Limits::default()
        )
        .unwrap()
        .matches(&view)
        .unwrap()
    );
    assert!(
        Filter::compile(
            "lower(raw.bytes) == ff:c3:9f:61:62",
            &registry,
            Limits::default()
        )
        .unwrap()
        .matches(&view)
        .unwrap()
    );
    assert!(
        Filter::compile(
            "upper(raw.bytes) == ff:c3:9f:41:42",
            &registry,
            Limits::default()
        )
        .unwrap()
        .matches(&view)
        .unwrap()
    );
}

#[test]
fn compiled_regex_storage_is_shared_by_every_pattern_in_the_filter() {
    let registry = builtin::registry();
    let term = r#"raw.bytes matches "a{1000}""#;
    assert!(Filter::compile(term, &registry, Limits::default()).is_ok());
    let expression = std::iter::repeat_n(term, 1024)
        .collect::<Vec<_>>()
        .join(" || ");
    assert!(Filter::compile(&expression, &registry, Limits::default()).is_err());
}
