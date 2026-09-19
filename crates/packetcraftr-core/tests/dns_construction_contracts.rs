// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    build, codec, decode, document, expression,
    field::{FieldValue, WireValue},
    filter,
    frame::{Frame, LinkType},
    fuzz,
    layer::Layer,
    protocol::{
        application::dns::{Dns, Name},
        builtin,
    },
    template::Template,
};
use std::time::UNIX_EPOCH;

fn packet() -> packetcraftr_core::packet::Packet {
    expression::parse(
        r#"ipv4(source=192.0.2.1,destination=192.0.2.53)/udp(source_port=12345,destination_port=53)/dns(id=7,response=true,questions=[{name="example.test.",type=1,class=1}],answers=[{owner="example.test.",ttl=60,value={kind=a,address=192.0.2.8}}],additionals=[{owner=".",value={kind=opt,udp_payload_size=1232,dnssec_ok=true}}])"#,
        &builtin::registry(), Default::default(),
    ).unwrap()
}

#[test]
fn named_recipes_build_dns_and_support_nested_filters_templates_and_fuzzing() {
    let registry = builtin::registry();
    let builder = build::Builder::new(registry.clone());
    let base = packet();
    let template =
        Template::new(base.clone()).axis(2, "questions[0].type", vec![1u16.into(), 28u16.into()]);
    for (index, packet) in template.expand(2).unwrap().enumerate() {
        let built = builder
            .build(packet.unwrap(), Default::default(), Default::default())
            .unwrap();
        let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, built.bytes).unwrap();
        let decoded = decode::Dissector::new(registry.clone())
            .decode(frame, Default::default())
            .unwrap();
        let dns = decoded.packet.get::<Dns>().unwrap();
        assert_eq!(dns.question_count, WireValue::Exact(1));
        assert_eq!(dns.answer_count, WireValue::Exact(1));
        assert_eq!(dns.questions[0].query_type, [1, 28][index]);
        let filter = filter::Filter::compile("dns.answers[0].value.address == 192.0.2.8 && dns.questions[0].name == \"example.test.\"", &registry, Default::default()).unwrap();
        assert!(
            filter
                .matches(&filter::Context {
                    decoded: &decoded,
                    derived: &[],
                    number: 1,
                    tcp_stream: None,
                    udp_stream: None
                })
                .unwrap()
        );
    }
    assert!(
        filter::Filter::compile(
            "dns.questions[0].missing == 1",
            &registry,
            Default::default()
        )
        .is_err()
    );
    let report = fuzz::run(
        &fuzz::Request {
            cases: 4,
            targets: vec!["2.questions[0].type".parse().unwrap()],
            strategies: vec![fuzz::Strategy::Boundary],
            ..Default::default()
        },
        base,
        registry,
    )
    .unwrap();
    assert_eq!(report.cases.len(), 4);
    assert!(report.cases.iter().any(|case| case.built.is_some()));
}

#[test]
fn wire_images_survive_documents_and_explicit_edits_rebuild_counts() {
    let original = Bytes::from_static(b"\x12\x34\x81\x80\0\x01\0\x01\0\0\0\0\x01a\0\0\x01\0\x01\xc0\x0c\0\x01\0\x01\0\0\0\x01\0\x04\xc0\0\x02\x08");
    let dns = Dns::try_from(original.clone()).unwrap();
    let mut packet = packetcraftr_core::packet::Packet::new();
    packet.push(dns);
    let document = document::Packet::from_packet(&packet);
    let recreated = document.to_packet(&builtin::registry(), 8).unwrap();
    assert_eq!(recreated.get::<Dns>().unwrap().to_wire().unwrap(), original);
    let mut edited = recreated.get::<Dns>().unwrap().clone();
    edited
        .set_field_path("answers[0].owner", "different.example.test.".into())
        .unwrap();
    edited.edit(|message| message.answers.clear());
    let decoded = Dns::try_from(edited.to_wire().unwrap()).unwrap();
    assert_eq!(decoded.answer_count, WireValue::Exact(0));
    assert_eq!(decoded.questions.len(), 1);
}

#[test]
fn nested_paths_require_list_indices_and_template_axes_normalize_them() {
    let registry = builtin::registry();
    for path in ["dns.questions.name", "dns.questions[0][0].name"] {
        assert!(
            filter::Filter::compile(
                &format!("{path} == \"example.test.\""),
                &registry,
                Default::default(),
            )
            .is_err(),
            "accepted invalid path {path}"
        );
    }
    let template = Template::new(packet())
        .axis(2, "questions[0].type", vec![1u16.into()])
        .axis(2, "questions[00].type", vec![28u16.into()]);
    assert!(matches!(
        template.expand(1),
        Err(packetcraftr_core::template::Error::DuplicateAxis { field, .. })
            if field == "questions[0].type"
    ));
}

#[test]
fn explicit_bad_counts_require_permissive_mode_and_keep_exact_bytes() {
    let mut packet = packet();
    packet
        .get_mut::<Dns>()
        .unwrap()
        .set_field(
            "answer_count",
            FieldValue::Bytes(Bytes::from_static(&[0xff, 0xff])),
        )
        .unwrap();
    let builder = build::Builder::new(builtin::registry());
    assert!(
        builder
            .build(packet.clone(), Default::default(), Default::default())
            .is_err()
    );
    let built = builder
        .build(
            packet,
            Default::default(),
            build::Options {
                mode: codec::Mode::Permissive,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(&built.bytes[34..36], &[0xff, 0xff]);
    assert!(!built.diagnostics.is_empty());
}

#[test]
fn dns_names_preserve_binary_labels_and_reject_overlong_or_invalid_escapes() {
    let name: Name = r"a\000\046\255.example.".parse().unwrap();
    assert_eq!(name.labels()[0].as_ref(), &[b'a', 0, b'.', 255]);
    assert_eq!(name.to_string().parse::<Name>().unwrap(), name);
    for invalid in ["", "a..b", "\\999.", "\\1", "\\12x"] {
        assert!(invalid.parse::<Name>().is_err());
    }
    assert!(format!("{}.", "a".repeat(64)).parse::<Name>().is_err());
}

#[test]
fn named_object_documents_charge_members_keys_and_nesting_in_both_formats() {
    let value = serde_json::json!({"schema":"packetcraftr.packet/v2","layers":[{"protocol":"raw","fields":{"fixture":{"type":"object","value":{"member":{"type":"unsigned","value":1}}}}}]});
    let text = serde_json::to_string(&value).unwrap();
    for format in [document::Format::Json, document::Format::Yaml] {
        let limits = document::DocumentLimits {
            max_total_payload_bytes: 14,
            ..Default::default()
        };
        assert!(document::Packet::parse_with_limits(&text, format, &limits).is_ok());
        for limits in [
            document::DocumentLimits {
                max_total_payload_bytes: 13,
                ..limits
            },
            document::DocumentLimits {
                max_list_items: 0,
                ..limits
            },
            document::DocumentLimits {
                max_nesting: 0,
                ..limits
            },
        ] {
            assert!(document::Packet::parse_with_limits(&text, format, &limits).is_err());
        }
    }
    let duplicate = text.replace(
        "\"member\":",
        "\"member\":{\"type\":\"unsigned\",\"value\":2},\"member\":",
    );
    assert!(
        document::Packet::parse_with_limits(
            &duplicate,
            document::Format::Json,
            &Default::default()
        )
        .is_err()
    );
}
