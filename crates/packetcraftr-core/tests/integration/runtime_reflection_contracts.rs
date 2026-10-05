// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use bytes::Bytes;
use common::probe::{Child, Probe, probe_layout};
use packetcraftr_core::field::{self, FieldValue};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::layout::{ByteRange, FieldLayout};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::Ipv4;

#[test]
fn reflected_cover_fail_closed() {
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

#[test]
fn typed_iteration_pkt_order() {
    let mut packet = Packet::new();
    packet.push(Probe {
        value: 1,
        ..Probe::default()
    });
    packet.push(Raw::new(Bytes::from_static(b"\xAA\xBB")));
    packet.push(Child { value: 7 });
    packet.push(Probe {
        value: 2,
        ..Probe::default()
    });
    packet.push(Probe {
        value: 3,
        ..Probe::default()
    });

    let forward: Vec<u8> = packet.iter_of::<Probe>().map(|probe| probe.value).collect();
    assert_eq!(forward, [1, 2, 3]);
    let reverse: Vec<u8> = packet
        .iter_of::<Probe>()
        .rev()
        .map(|probe| probe.value)
        .collect();
    assert_eq!(reverse, [3, 2, 1]);

    let mut mixed = packet.iter_of::<Probe>();
    assert_eq!(mixed.next().map(|probe| probe.value), Some(1));
    assert_eq!(mixed.next_back().map(|probe| probe.value), Some(3));
    assert_eq!(mixed.next().map(|probe| probe.value), Some(2));
    assert!(mixed.next().is_none());
    assert!(mixed.next_back().is_none());

    assert_eq!(packet.iter_of::<Raw>().count(), 1);
    assert_eq!(
        packet
            .iter_of::<Child>()
            .map(|child| child.value)
            .collect::<Vec<u8>>(),
        [7]
    );
    assert_eq!(packet.iter_of::<Ipv4>().count(), 0);
    assert!(Packet::new().iter_of::<Probe>().next().is_none());

    let mut repeated = Packet::new();
    for identification in [10_u16, 20, 30] {
        repeated.push(Ipv4 {
            identification,
            ..Ipv4::default()
        });
    }
    assert_eq!(
        repeated
            .iter_of::<Ipv4>()
            .nth(1)
            .map(|layer| layer.identification),
        Some(20)
    );
}

#[test]
fn mutable_typed_matching_layers() {
    let mut packet = Packet::new();
    packet.push(Probe {
        value: 1,
        ..Probe::default()
    });
    packet.push(Raw::new(Bytes::from_static(b"\xAA\xBB")));
    packet.push(Child { value: 7 });
    packet.push(Probe {
        value: 2,
        ..Probe::default()
    });
    packet.push(Probe {
        value: 3,
        ..Probe::default()
    });

    for probe in packet.iter_of_mut::<Probe>() {
        probe.value += 10;
    }
    assert_eq!(
        packet
            .iter_of::<Probe>()
            .map(|probe| probe.value)
            .collect::<Vec<u8>>(),
        [11, 12, 13]
    );

    for (assigned, probe) in (30_u8..).zip(packet.iter_of_mut::<Probe>().rev()) {
        probe.value = assigned;
    }
    assert_eq!(
        packet
            .iter_of::<Probe>()
            .map(|probe| probe.value)
            .collect::<Vec<u8>>(),
        [32, 31, 30]
    );

    {
        let mut ends = packet.iter_of_mut::<Probe>();
        ends.next().expect("front match").value = 40;
        ends.next_back().expect("back match").value = 50;
        assert_eq!(ends.next().map(|probe| probe.value), Some(31));
        assert!(ends.next().is_none());
        assert!(ends.next_back().is_none());
    }
    assert_eq!(
        packet
            .iter_of::<Probe>()
            .map(|probe| probe.value)
            .collect::<Vec<u8>>(),
        [40, 31, 50]
    );

    assert_eq!(packet.len(), 5);
    assert_eq!(
        packet.get::<Raw>().map(|raw| raw.bytes.as_ref()),
        Some(&b"\xAA\xBB"[..])
    );
    assert_eq!(packet.get::<Child>().map(|child| child.value), Some(7));
    assert_eq!(packet.iter_of_mut::<Ipv4>().count(), 0);
    assert!(Packet::new().iter_of_mut::<Child>().next().is_none());
}
