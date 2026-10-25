// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[test]
fn mqtt_fields_are_editable() {
    let reg = builtin::registry();
    let context = DecodeContext {
        parent: None,
        registry: &reg,
        network: None,
        hop_limit: None,
        discriminator: None,
    };
    let mut decoded = reg
        .codec("mqtt")
        .unwrap()
        .decode(Bytes::from_static(&[0x30, 4, 0, 1, b'a', b'x']), &context)
        .unwrap();
    assert_eq!(
        decoded.layer.field("packet_type"),
        Some(crate::field::Value::Unsigned(3))
    );
    assert_eq!(
        decoded.layer.field("topic"),
        Some(crate::field::Value::Bytes(Bytes::from_static(b"a")))
    );
    assert_eq!(
        decoded.layer.field("payload"),
        Some(crate::field::Value::Bytes(Bytes::from_static(b"x")))
    );
    decoded
        .layer
        .set_field(
            "topic",
            crate::field::Value::Bytes(Bytes::from_static(b"next")),
        )
        .unwrap();
    assert_eq!(
        decoded.layer.field("topic"),
        Some(crate::field::Value::Bytes(Bytes::from_static(b"next")))
    );
    let mut packet = Packet::new();
    packet.push_boxed(decoded.layer);
    let built = crate::build::Builder::new(reg)
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    // MQTT 3.1.1 section 3.3, checked 2026-10-25.
    // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
    assert_eq!(built.bytes.as_ref(), b"\x30\x07\0\x04nextx");
}

#[test]
fn dtls_document_rejects_oversized_fragment_offsets_without_panicking() {
    let fragment = field::Value::Object(record([
        ("message_type", 1_u8.into()),
        ("length", 1_u8.into()),
        ("message_sequence", 0_u8.into()),
        ("offset", u64::MAX.into()),
        ("data", Bytes::from_static(b"x").into()),
    ]));
    let mut packet = Packet::new();
    packet.push(Dtls {
        records: Records(vec![record([
            ("content_type", 22_u8.into()),
            ("epoch", 0_u8.into()),
            ("sequence", 0_u8.into()),
            ("handshakes", field::Value::List(vec![fragment])),
        ])]),
    });
    let json = serde_json::to_string(&document::Packet::from_packet(&packet)).unwrap();
    let document = document::Packet::parse(&json, document::Format::Json, json.len()).unwrap();
    let registry = builtin::registry();
    let packet = document.to_packet(&registry, 16).unwrap();
    assert!(
        crate::build::Builder::new(registry)
            .build(packet, Addresses::default(), Default::default())
            .is_err()
    );
}

#[test]
fn sflow_sample_members_support_editing_and_projection() {
    let registry = builtin::registry();
    let json = include_str!("../../../../../../examples/documents/packet-sflow.json");
    let document = document::Packet::parse(json, document::Format::Json, json.len()).unwrap();
    let mut packet = document.to_packet(&registry, 64).unwrap();
    let sflow = packet.get_mut::<Sflow>().unwrap();
    for name in [
        "sampling_rate",
        "sample_pool",
        "drops",
        "input",
        "output",
        "source_type",
        "source_index",
        "input_format",
        "output_format",
        "padding",
    ] {
        let path: field::Path = format!("samples[0].{name}").parse().unwrap();
        assert!(
            path.schema(sflow.schema()).is_some(),
            "missing sample member {name}"
        );
    }
    for name in ["format", "data", "padding"] {
        let path: field::Path = format!("samples[0].records[0].{name}").parse().unwrap();
        assert!(
            path.schema(sflow.schema()).is_some(),
            "missing record member {name}"
        );
    }
    let path: field::Path = "samples[0].sampling_rate".parse().unwrap();
    sflow.set_field_path(&path, 200_u32.into()).unwrap();
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let decoded = crate::decode::Dissector::new(registry.clone())
        .decode(
            Frame::without_timestamp(LinkType::ETHERNET, built.bytes).unwrap(),
            Default::default(),
        )
        .unwrap();
    let projection =
        crate::filter::Projection::compile(["sflow#1.samples[0].sampling_rate"], &registry)
            .unwrap();
    assert_eq!(
        projection
            .values(&crate::filter::Context::frame(&decoded, 1), 4096)
            .unwrap(),
        vec![Some(field::Value::Unsigned(200))]
    );
}

#[test]
fn ipfix_and_dtls_nested_fields_support_editing_and_projection() {
    for (name, json, path, value, members) in [
        (
            "ipfix",
            include_str!("../../../../../../examples/documents/packet-ipfix.json"),
            "sets[0].records[0].fields[0].length",
            8_u64,
            vec![
                "sets[0].records[0].template_id",
                "sets[0].records[0].scope_count",
                "sets[0].records[0].fields[0].element_id",
                "sets[0].records[0].fields[0].enterprise",
            ],
        ),
        (
            "dtls",
            include_str!("../../../../../../examples/documents/packet-dtls.json"),
            "records[0].handshakes[0].message_sequence",
            2_u64,
            vec![
                "records[0].handshakes[0].message_type",
                "records[0].handshakes[0].length",
                "records[0].handshakes[0].offset",
                "records[0].handshakes[0].data",
            ],
        ),
    ] {
        let registry = std::sync::Arc::new(
            builtin::registry_with(|builder| {
                if name == "dtls" {
                    builder.bind("udp", 5684, "dtls", i32::MAX)?;
                }
                Ok(())
            })
            .unwrap(),
        );
        let document = document::Packet::parse(json, document::Format::Json, json.len()).unwrap();
        let mut packet = document.to_packet(&registry, 64).unwrap();
        let index = packet
            .iter()
            .position(|layer| layer.protocol_id().as_str() == name)
            .unwrap();
        let layer = packet.layer_mut(index).unwrap();
        for member in members {
            assert!(
                member
                    .parse::<field::Path>()
                    .unwrap()
                    .schema(layer.schema())
                    .is_some(),
                "{name}.{member}"
            );
        }
        layer
            .set_field_path(&path.parse().unwrap(), value.into())
            .unwrap();
        if let Some(tcp) = packet.get_mut::<Tcp>() {
            tcp.checksum = field::WireValue::Auto;
        }
        if let Some(udp) = packet.get_mut::<Udp>() {
            udp.checksum = field::WireValue::Auto;
        }
        let built = crate::build::Builder::new(registry.clone())
            .build(packet, Addresses::default(), Default::default())
            .unwrap();
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                Frame::without_timestamp(LinkType::ETHERNET, built.bytes).unwrap(),
                Default::default(),
            )
            .unwrap();
        let column = format!("{name}#1.{path}");
        let projection = crate::filter::Projection::compile([column.as_str()], &registry).unwrap();
        assert_eq!(
            projection
                .values(&crate::filter::Context::frame(&decoded, 1), 4096)
                .unwrap(),
            vec![Some(value.into())]
        );
    }
}

#[test]
fn resp_payloads_support_typed_edits_filters_and_projection() {
    use crate::protocol::application::resp::{Resp, RespValue};
    for (value, path, replacement, literal) in [
        (
            RespValue::Simple(Bytes::from_static(b"OK")),
            "value.data",
            Bytes::from_static(b"NEXT").into(),
            "b\"NEXT\"",
        ),
        (
            RespValue::Integer(7),
            "value.data",
            field::Value::Signed(9),
            "9",
        ),
        (
            RespValue::Array(Some(vec![RespValue::Simple(Bytes::from_static(b"OK"))])),
            "value.data[0].data",
            Bytes::from_static(b"NEXT").into(),
            "b\"NEXT\"",
        ),
    ] {
        let registry = builtin::registry();
        let mut resp = Resp { value };
        resp.set_field_path(&path.parse().unwrap(), replacement.clone())
            .unwrap();
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(Ipv4::default());
        packet.push(Tcp {
            destination_port: 6379,
            ..Default::default()
        });
        packet.push(resp);
        let built = crate::build::Builder::new(registry.clone())
            .build(packet, Addresses::default(), Default::default())
            .unwrap();
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                Frame::without_timestamp(LinkType::ETHERNET, built.bytes).unwrap(),
                Default::default(),
            )
            .unwrap();
        let column = format!("resp#1.{path}");
        let projection = crate::filter::Projection::compile([column.as_str()], &registry).unwrap();
        let context = crate::filter::Context::frame(&decoded, 1);
        assert_eq!(
            projection.values(&context, 4096).unwrap(),
            vec![Some(replacement)]
        );
        assert!(
            crate::filter::Filter::compile(
                &format!("{column} == {literal}"),
                &registry,
                Default::default()
            )
            .unwrap()
            .matches(&context)
            .unwrap()
        );
        if path.contains("[0]") {
            let projection =
                crate::filter::Projection::compile(["resp.value.data[*].data"], &registry).unwrap();
            assert_eq!(
                projection.values(&context, 4096).unwrap(),
                vec![Some(field::Value::List(vec![
                    Bytes::from_static(b"NEXT").into()
                ]))]
            );
        }
    }
}

#[test]
fn interleaved_rtsp_layout_only_contains_binary_fields() {
    // https://datatracker.ietf.org/doc/html/rfc2326#section-10.12 checked 2026-10-25.
    let registry = builtin::registry();
    let mut packet = Packet::new();
    packet.push(crate::protocol::application::rtsp::Rtsp {
        interleaved: true,
        channel: 7,
        body: Bytes::from_static(b"\r\n\r\n"),
        ..Default::default()
    });
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(built.bytes.as_ref(), b"$\x07\0\x04\r\n\r\n");
    let fields = &built.layout.layer(0).unwrap().fields;
    assert_eq!(
        fields
            .iter()
            .map(|field| field.name)
            .collect::<std::collections::BTreeSet<_>>(),
        ["interleaved", "channel", "body"].into_iter().collect()
    );
    for (name, expected) in [("channel", b"\x07".as_slice()), ("body", b"\r\n\r\n")] {
        let range = fields
            .iter()
            .find(|field| field.name == name)
            .unwrap()
            .range;
        assert_eq!(&built.bytes[range.start..range.end], expected);
    }
    let decoded = registry
        .codec("rtsp")
        .unwrap()
        .decode(
            built.bytes.clone(),
            &DecodeContext {
                parent: None,
                registry: &registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )
        .unwrap();
    assert_fields(
        decoded.layer.as_ref(),
        &[
            ("interleaved", true.into()),
            ("channel", 7_u8.into()),
            ("body", Bytes::from_static(b"\r\n\r\n").into()),
        ],
    );
    for (name, expected) in [("channel", b"\x07".as_slice()), ("body", b"\r\n\r\n")] {
        let range = decoded
            .fields
            .iter()
            .find(|field| field.name == name)
            .unwrap()
            .range;
        assert_eq!(&built.bytes[range.start..range.end], expected);
    }
}

#[test]
fn resp_null_reflection_requires_canonical_empty_data() {
    use crate::{field::Value, layer::ReflectiveField, protocol::application::resp::RespValue};
    for (kind, good, bad, expected) in [
        (
            "null_bulk",
            Value::Bytes(Bytes::new()),
            Value::Bytes(Bytes::from_static(b"discarded")),
            RespValue::Bulk(None),
        ),
        (
            "null_array",
            Value::List(vec![]),
            Value::List(vec![Value::Unsigned(1)]),
            RespValue::Array(None),
        ),
    ] {
        let value = |data| {
            Value::Object(
                [
                    ("kind".into(), Value::Text(kind.into())),
                    ("data".into(), data),
                ]
                .into(),
            )
        };
        let mut resp = RespValue::Integer(1);
        resp.set_reflective_value(value(good)).unwrap();
        assert_eq!(resp, expected);
        assert!(resp.set_reflective_value(value(bad)).is_err());
        assert!(
            resp.set_reflective_value(value(Value::Bool(false)))
                .is_err()
        );
    }
}

#[test]
fn application_layouts_expose_exact_content_ranges() {
    for (name, version) in [("sip", "SIP/2.0"), ("rtsp", "RTSP/1.0")] {
        let wire = format!("OPTIONS * {version}\r\nContent-Length:3\r\n\r\nabc");
        assert_eq!(slice(name, "body", wire.as_bytes()), b"abc");
        let empty = format!("OPTIONS * {version}\r\nContent-Length:0\r\n\r\n");
        assert_eq!(slice(name, "body", empty.as_bytes()), b"");
    }
    assert_eq!(slice("rtsp", "body", b"$\x02\0\x03abc"), b"abc");
    let mut memcached = vec![0x80, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 6];
    memcached.extend_from_slice(&[0; 12]);
    memcached.extend_from_slice(b"EKEval");
    for (field, expected) in [
        ("extras", b"E".as_slice()),
        ("key", b"KE"),
        ("value", b"val"),
    ] {
        assert_eq!(slice("memcached", field, &memcached), expected);
    }
    let ldap = b"\x30\x0a\x02\x01\x07\x65\x03\x0a\x01\0\xa0\0";
    for (field, expected) in [
        ("message_id", b"\x07".as_slice()),
        ("operation", b"\x65"),
        ("fields", b"\x0a\x01\0"),
        ("controls", b"\xa0\0"),
    ] {
        assert_eq!(slice("ldap", field, ldap), expected);
    }
    // Long-form lengths at both envelope and operation boundaries retain offsets.
    let mut operation = vec![4, 127];
    operation.extend([b'x'; 127]);
    let mut long_ldap = vec![0x30, 0x81, 137, 2, 1, 7, 0x65, 0x81, 129];
    long_ldap.extend_from_slice(&operation);
    long_ldap.extend_from_slice(&[0xa0, 0]);
    assert_eq!(slice("ldap", "message_id", &long_ldap), b"\x07");
    assert_eq!(slice("ldap", "fields", &long_ldap), operation);
    assert_eq!(slice("ldap", "controls", &long_ldap), b"\xa0\0");
    let coap = b"\x42\x01\0\x01TK\xb1x\x01y\xffPAY";
    for (field, expected) in [
        ("token", b"TK".as_slice()),
        ("options", b"\xb1x\x01y"),
        ("payload", b"PAY"),
    ] {
        assert_eq!(slice("coap", field, coap), expected);
    }
    for field in ["token", "options", "payload"] {
        assert_eq!(slice("coap", field, b"\x40\x01\0\x01"), b"");
    }
}
