// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use bytes::Bytes;
use common::probe::{Probe, probe_layout};
use packetcraftr_core::field::{self, FieldValue};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::layout::{ByteRange, FieldLayout};

#[test]
fn reflected_fields_cover_supported_types_and_fail_closed() {
    let mut layer = Probe::default();
    layer.set_field("enabled", true.into()).expect("bool");
    layer.set_field("label", "renamed".into()).expect("text");
    layer
        .set_field("bytes", vec![1, 2, 3].into())
        .expect("bytes");
    layer
        .set_field("ipv4", "192.0.2.4".into())
        .expect("IPv4 text");
    layer
        .set_field("ipv6", "2001:db8::4".into())
        .expect("IPv6 text");
    layer
        .set_field("mac", "00-11-22-33-44-55".into())
        .expect("MAC text");
    layer
        .set_field("token", FieldValue::Bytes(Bytes::from_static(b"12345678")))
        .expect("eight-byte token");
    layer
        .set_field("wire", "AUTO".into())
        .expect("auto wire value");
    assert_eq!(
        layer.field("wire"),
        Some(FieldValue::Text("auto".to_owned()))
    );
    layer
        .set_field("wire", 65_535_u64.into())
        .expect("exact wire value");
    assert_eq!(layer.wire.exact(), Some(&65_535));
    layer
        .set_field("wire", FieldValue::Bytes(Bytes::from_static(b"raw")))
        .expect("raw wire value");

    assert!(matches!(
        layer.set_field("enabled", 1_u8.into()),
        Err(field::Error::WrongType {
            expected: "bool",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("ipv4", "not-an-address".into()),
        Err(field::Error::WrongType {
            expected: "ipv4",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("ipv6", false.into()),
        Err(field::Error::WrongType {
            expected: "ipv6",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("mac", "00:11:22".into()),
        Err(field::Error::WrongType {
            expected: "mac address",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("token", vec![1, 2].into()),
        Err(field::Error::WrongType {
            expected: "eight bytes",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("wire", "manual".into()),
        Err(field::Error::WrongType {
            expected: "unsigned, bytes, or 'auto'",
            ..
        })
    ));

    let schema = layer.schema();
    assert_eq!(schema.name, "Probe");
    layer
        .validate_required_fields()
        .expect("all required getters produce values");
    assert_eq!(
        probe_layout(),
        vec![FieldLayout {
            name: "value",
            range: ByteRange::new(0, 1)
        }]
    );
    assert_eq!(Raw::layout(3)[0].range, ByteRange::new(0, 3));
}
