// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::{Context, Error, Filter, Projection};
use crate::{
    codec::Addresses,
    decode::DecodedPacket,
    field,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{
        application::resp::{Resp, RespValue},
        builtin,
        link::Ethernet,
        network::Ipv4,
        transport::Tcp,
    },
    registry::Registry,
};

fn decoded(registry: &std::sync::Arc<Registry>) -> DecodedPacket {
    let mut packet = Packet::default();
    packet.push(Ethernet {
        source: [0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc],
        ..Default::default()
    });
    packet.push(Ipv4::default());
    packet.push(Tcp {
        destination_port: 6379,
        ..Default::default()
    });
    packet.push(Resp {
        value: RespValue::Array(Some(vec![
            RespValue::Simple(Bytes::from_static(b"OK")),
            RespValue::Simple(Bytes::from_static(b"LAST")),
        ])),
    });
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    crate::decode::Dissector::new(registry.clone())
        .decode(
            Frame::new(None, LinkType::ETHERNET, built.bytes).unwrap(),
            Default::default(),
        )
        .unwrap()
}

#[test]
fn slices_selectors_occurrences_and_measures_read_the_intended_values() {
    let registry = builtin::registry();
    let decoded = decoded(&registry);
    let context = Context::frame(&decoded, 1);
    for (source, expected) in [
        ("ethernet.source[0:3] == 00:1b:21", true),
        ("ethernet.source[0:3] == 00:1b:22", false),
        ("ethernet.source[3] == b\"\\xaa\"", true),
        ("ethernet.source[:2] == 00:1b", true),
        ("ethernet.source[4:] == bb:cc", true),
        ("resp.value.data[*].data == b\"LAST\"", true),
        ("resp.value.data[*].data == b\"NONE\"", false),
        ("resp.value.data[-1].data == b\"OK\"", false),
        ("resp.value.data[-1].data == b\"LAST\"", true),
        ("resp.value.data[0].data == b\"OK\"", true),
        ("resp.value.data[-1].data[0:2] == b\"LA\"", true),
        ("resp.value.data[*].data[1:2] == b\"K\"", true),
        ("count(resp.value.data) == 2", true),
        ("len(resp.value.data[0].data) == 2", true),
        ("len(ethernet.source[1:4]) == 3", true),
        ("ipv4#last && ipv4#1 && !ipv4#2", true),
        ("ipv4#-1.ttl == 64", true),
        ("ipv4#2.ttl == 64", false),
        ("ipv4#last.ttl == 63", false),
    ] {
        let filter = Filter::compile(source, &registry, Default::default())
            .unwrap_or_else(|error| panic!("{source}: {error}"));
        assert_eq!(filter.matches(&context).unwrap(), expected, "{source}");
    }
}

#[test]
fn unsliceable_and_unmeasurable_paths_are_refused_in_check_order() {
    let registry = builtin::registry();
    for (source, unsliceable) in [
        ("frame.len[0:1] == 00", true),
        ("tcp.stream[0] == 00", true),
        ("tcp.destination_port[0] == 00", true),
        ("frame.len[2:1] == 00", false),
        ("frame.len[x] == 00", false),
        ("count(ethernet.source[0:2]) == 1", false),
    ] {
        let error = Filter::compile(source, &registry, Default::default()).unwrap_err();
        assert_eq!(
            matches!(error, Error::UnsliceableField { .. }),
            unsliceable,
            "{source}: {error:?}"
        );
        assert!(
            unsliceable || matches!(error, Error::Syntax { .. }),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn projections_gather_all_selected_elements_and_pick_one_for_the_last() {
    let registry = builtin::registry();
    let decoded = decoded(&registry);
    let context = Context::frame(&decoded, 1);
    let projection = Projection::compile(
        [
            "resp.value.data[*].data",
            "resp.value.data[-1].data",
            "ethernet.source[0:2]",
            "resp.value.data[-1].data[1:3]",
        ],
        &registry,
    )
    .unwrap();
    assert_eq!(
        projection.values(&context, 4096).unwrap(),
        vec![
            Some(field::Value::List(vec![
                Bytes::from_static(b"OK").into(),
                Bytes::from_static(b"LAST").into(),
            ])),
            Some(Bytes::from_static(b"LAST").into()),
            Some(Bytes::from_static(&[0x00, 0x1b]).into()),
            Some(Bytes::from_static(b"AS").into()),
        ]
    );
}
