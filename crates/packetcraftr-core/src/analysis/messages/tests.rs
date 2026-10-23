// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::analysis::{
    provenance::{SourceFrame, Tracker},
    reassembly::tcp::FlowKey,
    scope::Interner,
};
use std::time::UNIX_EPOCH;
fn flow() -> ScopedFlowKey {
    ScopedFlowKey {
        scope: Interner::new().intern(None, vec![]).unwrap(),
        flow: FlowKey {
            source: "192.0.2.1".parse().unwrap(),
            source_port: 40000,
            destination: "192.0.2.2".parse().unwrap(),
            destination_port: 1883,
        },
    }
}
fn deliver(
    collector: &mut Collector,
    tracker: &Tracker,
    number: u64,
    bytes: &[u8],
    generation: u64,
    out: &mut Vec<Event>,
) {
    collector
        .data(
            application::Delivery {
                flow: flow(),
                stream: 0,
                generation,
                bytes: Bytes::copy_from_slice(bytes),
                sources: tracker
                    .single(SourceFrame {
                        number,
                        timestamp: UNIX_EPOCH,
                    })
                    .unwrap(),
            },
            out,
        )
        .unwrap();
}
#[test]
fn split_mqtt_and_coalesced_messages_keep_sources() {
    let wire = [0x30, 4, 0, 1, b'a', b'x'];
    for split in 1..wire.len() {
        let mut c = Collector::new(
            Limits::default(),
            crate::protocol::builtin::registry(),
            [BuiltinProtocol::Mqtt],
        )
        .unwrap();
        let t = Tracker::new(1 << 20, 32).unwrap();
        let mut out = vec![];
        deliver(&mut c, &t, 1, &wire[..split], 0, &mut out);
        assert!(out.is_empty());
        let mut tail = wire[split..].to_vec();
        tail.extend([0xc0, 0]);
        deliver(&mut c, &t, 2, &tail, 0, &mut out);
        assert_eq!(out.len(), 2);
        let Event::Message(first) = &out[0] else {
            panic!()
        };
        assert_eq!(first.status, Status::Complete);
        assert_eq!(first.wire.as_ref(), wire);
        assert_eq!(
            first.sources.iter().map(|f| f.number).collect::<Vec<_>>(),
            vec![1, 2]
        );
        let Event::Message(second) = &out[1] else {
            panic!()
        };
        assert_eq!(second.sources.len(), 1);
        assert_eq!(c.buffered, 0);
    }
}
#[test]
fn gap_stops_direction_until_new_generation() {
    let mut c = Collector::new(
        Limits::default(),
        crate::protocol::builtin::registry(),
        [BuiltinProtocol::Mqtt],
    )
    .unwrap();
    let t = Tracker::new(1 << 20, 32).unwrap();
    let mut out = vec![];
    deliver(&mut c, &t, 1, &[0x30, 4], 0, &mut out);
    c.event(
        application::Event::Gap {
            flow: flow(),
            stream: 0,
        },
        2,
        &mut out,
    )
    .unwrap();
    assert!(matches!(&out[1],Event::Message(m)if m.status==Status::Gap));
    deliver(&mut c, &t, 3, &[0xc0, 0], 0, &mut out);
    assert_eq!(out.len(), 2);
    deliver(&mut c, &t, 4, &[0xc0, 0], 1, &mut out);
    assert!(matches!(&out[2],Event::Message(m)if m.status==Status::Complete&&m.generation==1));
}

#[test]
fn every_tcp_protocol_accepts_split_and_coalesced_frames() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    for row in manifest["protocols"].as_array().unwrap() {
        let name = row["protocol"].as_str().unwrap();
        let protocol = BuiltinProtocol::from_name(name).unwrap();
        if !protocol.stream_decode() {
            continue;
        }
        let bytes = crate::layer::parse_hex(row["wire_hex"].as_str().unwrap()).unwrap();
        let port = protocol.message_protocol().unwrap().tcp_ports[0];
        let mut collector = Collector::new(
            Limits::default(),
            crate::protocol::builtin::registry(),
            [protocol],
        )
        .unwrap();
        let tracker = Tracker::new(1 << 20, 32).unwrap();
        let mut out = Vec::new();
        let mut f = flow();
        f.flow.destination_port = port;
        let doubled = bytes
            .iter()
            .chain(bytes.iter())
            .copied()
            .collect::<Vec<_>>();
        collector
            .data(
                application::Delivery {
                    flow: f,
                    stream: 0,
                    generation: 0,
                    bytes: doubled.into(),
                    sources: tracker
                        .single(SourceFrame {
                            number: 1,
                            timestamp: UNIX_EPOCH,
                        })
                        .unwrap(),
                },
                &mut out,
            )
            .unwrap();
        assert_eq!(out.len(), 2, "coalesced {name}");
        assert!(
            out.iter()
                .all(|event| matches!(event,Event::Message(m) if m.status==Status::Complete)),
            "coalesced {name}"
        );

        for split in 1..bytes.len() {
            let mut c = Collector::new(
                Limits::default(),
                crate::protocol::builtin::registry(),
                [protocol],
            )
            .unwrap();
            let tracker = Tracker::new(1 << 20, 32).unwrap();
            let mut out = Vec::new();
            let mut f = flow();
            f.flow.destination_port = port;
            for (number, input) in [(1, &bytes[..split]), (2, &bytes[split..])] {
                c.data(
                    application::Delivery {
                        flow: f.clone(),
                        stream: 0,
                        generation: 0,
                        bytes: Bytes::copy_from_slice(input),
                        sources: tracker
                            .single(SourceFrame {
                                number,
                                timestamp: UNIX_EPOCH,
                            })
                            .unwrap(),
                    },
                    &mut out,
                )
                .unwrap();
            }
            assert_eq!(out.len(), 1, "{name}, split {split}");
            assert!(
                matches!(&out[0],Event::Message(m) if m.status==Status::Complete),
                "{name}, split {split}: {out:?}"
            );
        }
    }
}

#[test]
fn declared_length_is_rejected_before_large_allocation() {
    let mut framer = Framer::new("opcua_tcp");
    assert!(framer.progress(b"MSGF\xff\xff\xff\x7f", 1024).is_err());
    let mut framer = Framer::new("resp");
    assert!(framer.progress(b"$2147483647\r\n", 1024).is_err());
}

#[test]
fn port_overrides_drive_stream_selection() {
    let registry = crate::protocol::builtin::registry_with(|builder| {
        builder.bind("tcp", 1884, "mqtt", i32::MAX).map(|_| ())
    })
    .unwrap();
    let mut collector = Collector::new(
        Limits::default(),
        Arc::new(registry),
        [BuiltinProtocol::Mqtt],
    )
    .unwrap();
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let mut events = Vec::new();
    let mut f = flow();
    f.flow.destination_port = 1884;
    collector
        .data(
            application::Delivery {
                flow: f,
                stream: 0,
                generation: 0,
                bytes: Bytes::from_static(&[0xc0, 0]),
                sources: tracker
                    .single(SourceFrame {
                        number: 1,
                        timestamp: UNIX_EPOCH,
                    })
                    .unwrap(),
            },
            &mut events,
        )
        .unwrap();
    assert!(matches!(&events[0],Event::Message(m) if m.protocol==BuiltinProtocol::Mqtt));
}

#[test]
fn capture_pipeline_reassembles_and_attributes_messages() {
    let registry = crate::protocol::builtin::registry();
    let collector =
        Collector::new(Limits::default(), registry.clone(), [BuiltinProtocol::Mqtt]).unwrap();
    let capture = include_bytes!("../../../../../examples/captures/protocol-mqtt-stream.pcap");
    let mut reader = crate::capture_file::Reader::new(&capture[..]).unwrap();
    let mut events = Vec::new();
    let outcome = crate::analysis::Session::new(registry, Default::default(), collector)
        .run(
            &mut reader,
            |_| Ok(()),
            |event| {
                events.push(event);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(outcome.summary.complete_messages, 2);
    let messages: Vec<_> = events
        .iter()
        .filter_map(|event| {
            if let Event::Message(m) = event {
                Some(m)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        messages[0]
            .sources
            .iter()
            .map(|s| s.number)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(
        messages[1]
            .sources
            .iter()
            .map(|s| s.number)
            .collect::<Vec<_>>(),
        vec![3]
    );
}

fn deliver_on(
    collector: &mut Collector,
    tracker: &Tracker,
    number: u64,
    flow: ScopedFlowKey,
    bytes: &[u8],
    generation: u64,
    out: &mut Vec<Event>,
) {
    collector
        .data(
            application::Delivery {
                flow,
                stream: 0,
                generation,
                bytes: Bytes::copy_from_slice(bytes),
                sources: tracker
                    .single(SourceFrame {
                        number,
                        timestamp: UNIX_EPOCH,
                    })
                    .unwrap(),
            },
            out,
        )
        .unwrap();
}

#[test]
fn review_selected_source_port_is_not_hidden_by_an_unselected_destination() {
    let mut collector = Collector::new(
        Limits::default(),
        crate::protocol::builtin::registry(),
        [BuiltinProtocol::Mqtt],
    )
    .unwrap();
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let mut response = flow().reverse();
    response.flow.destination_port = 44818;
    let mut events = Vec::new();
    deliver_on(
        &mut collector,
        &tracker,
        1,
        response,
        &[0xd0, 0],
        0,
        &mut events,
    );
    assert!(matches!(events.as_slice(), [Event::Message(message)]
        if message.protocol == BuiltinProtocol::Mqtt && message.status == Status::Complete));
}

#[test]
fn review_mqtt5_stays_opaque_in_both_directions_until_a_new_generation() {
    let connect5 = b"\x10\x0d\0\x04MQTT\x05\x02\0\x3c\0\0\0";
    let publish5 = b"\x30\x05\0\x01a\0x";
    for split in 1..connect5.len() {
        let mut collector = Collector::new(
            Limits::default(),
            crate::protocol::builtin::registry(),
            [BuiltinProtocol::Mqtt],
        )
        .unwrap();
        let tracker = Tracker::new(1 << 20, 32).unwrap();
        let mut events = Vec::new();
        deliver(
            &mut collector,
            &tracker,
            1,
            &connect5[..split],
            0,
            &mut events,
        );
        assert!(events.is_empty());
        let mut tail = connect5[split..].to_vec();
        tail.extend_from_slice(publish5);
        deliver(&mut collector, &tracker, 2, &tail, 0, &mut events);
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, Event::Message(message)
            if message.status == Status::Unsupported && message.packet.is_none()))
        );
        // MQTT 5 CONNACK, AUTH and PUBLISH remain framed but semantically opaque.
        let mut response = b"\x20\x03\0\0\0\xf0\x02\0\0".to_vec();
        response.extend_from_slice(publish5);
        deliver_on(
            &mut collector,
            &tracker,
            3,
            flow().reverse(),
            &response,
            0,
            &mut events,
        );
        assert_eq!(events.len(), 5);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, Event::Message(message)
            if message.status == Status::Unsupported && message.packet.is_none()))
        );
        assert!(matches!(&events[1], Event::Message(message) if message.wire.as_ref() == publish5));
        let mut next = b"\x10\x0c\0\x04MQTT\x04\x02\0\x3c\0\0".to_vec();
        next.extend_from_slice(b"\x30\x04\0\x01ax");
        deliver(&mut collector, &tracker, 4, &next, 1, &mut events);
        assert_eq!(events.len(), 7);
        assert!(
            events[5..]
                .iter()
                .all(|event| matches!(event, Event::Message(message)
            if message.status == Status::Complete && message.generation == 1))
        );
    }
}
