// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::analysis::{
    provenance::{SourceFrame, Tracker},
    reassembly::tcp::FlowKey,
    scope::Interner,
};
use std::time::{Duration, UNIX_EPOCH};

fn decoded_message(event: &Event) -> &Message {
    let Event::Message(message) = event else {
        panic!("expected a message, got {event:?}");
    };
    message
}

fn complete_message<'a>(
    event: &'a Event,
    protocol: BuiltinProtocol,
    wire: &[u8],
    sources: &[u64],
) -> &'a Message {
    let message = decoded_message(event);
    assert_eq!(message.status, Status::Complete);
    assert_eq!(message.protocol, protocol);
    assert_eq!(message.wire.as_ref(), wire);
    assert!(message.error.is_none(), "{:?}", message.error);
    assert!(
        message
            .packet
            .as_ref()
            .unwrap()
            .iter()
            .any(|layer| layer.protocol_id().as_str() == protocol.as_str())
    );
    assert_eq!(
        message
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>(),
        sources
    );
    message
}

fn assert_packet_fields(message: &Message, expected: &crate::document::Layer) {
    let layer = message
        .packet
        .as_ref()
        .unwrap()
        .iter()
        .find(|layer| layer.protocol_id().as_str() == expected.protocol)
        .unwrap();
    for (field, value) in &expected.fields {
        assert_eq!(
            layer.field(field).as_ref(),
            Some(value),
            "{}.{}",
            expected.protocol,
            field
        );
    }
}

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
                        timestamp: UNIX_EPOCH + Duration::from_secs(number),
                    })
                    .unwrap(),
            },
            out,
        )
        .unwrap();
}
#[test]
fn split_mqtt_and_coalesced_messages_keep_sources() {
    // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html section 3.3 checked 2026-10-25.
    let wire = [0x30, 4, 0, 1, b'a', b'x'];
    for split in 1..wire.len() {
        let mut c = Collector::new(
            Limits {
                max_buffer_bytes: 8,
                ..Limits::default()
            },
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
        let first = complete_message(&out[0], BuiltinProtocol::Mqtt, &wire, &[1, 2]);
        assert_eq!(
            first.sources.frames(),
            [
                SourceFrame {
                    number: 1,
                    timestamp: UNIX_EPOCH + Duration::from_secs(1)
                },
                SourceFrame {
                    number: 2,
                    timestamp: UNIX_EPOCH + Duration::from_secs(2)
                },
            ]
        );
        let mqtt = first
            .packet
            .as_ref()
            .unwrap()
            .get::<crate::protocol::application::mqtt::Mqtt>()
            .unwrap();
        assert_eq!(mqtt.packet_type, 3);
        assert_eq!(mqtt.topic.as_ref(), b"a");
        assert_eq!(mqtt.payload.as_ref(), b"x");
        complete_message(&out[1], BuiltinProtocol::Mqtt, &[0xc0, 0], &[2]);
        deliver(&mut c, &t, 3, &wire, 0, &mut out);
        assert_eq!(out.len(), 3);
        complete_message(&out[2], BuiltinProtocol::Mqtt, &wire, &[3]);
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
            generation: 0,
        },
        2,
        &mut out,
    )
    .unwrap();
    let [Event::Issue(issue), Event::Message(message)] = out.as_slice() else {
        panic!("expected a gap and its retained message: {out:?}");
    };
    assert_eq!(issue.status, Status::Gap);
    assert_eq!(issue.number, 2);
    assert_eq!(message.status, Status::Gap);
    assert_eq!(message.wire.as_ref(), b"\x30\x04");
    assert_eq!(
        message
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>(),
        [1]
    );
    assert!(message.packet.is_none());
    deliver(&mut c, &t, 3, &[0xc0, 0], 0, &mut out);
    assert_eq!(out.len(), 2);
    deliver(&mut c, &t, 4, &[0xc0, 0], 1, &mut out);
    let resumed = complete_message(&out[2], BuiltinProtocol::Mqtt, b"\xc0\0", &[4]);
    assert_eq!(resumed.generation, 1);
}

#[test]
fn every_tcp_protocol_accepts_split_and_coalesced_frames() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    let capabilities: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/documents/output-protocols-success.json"
    ))
    .unwrap();
    for advertised in capabilities["result"]["protocols"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["stream_decode"] == true)
    {
        let name = advertised["protocol"].as_str().unwrap();
        let row = manifest["protocols"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["protocol"] == name)
            .unwrap();
        let protocol = BuiltinProtocol::from_name(name).unwrap();
        let bytes = crate::layer::parse_hex(row["wire_hex"].as_str().unwrap()).unwrap();
        let document_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(row["packet_document"].as_str().unwrap());
        let json = std::fs::read_to_string(document_path).unwrap();
        let mut expected =
            crate::document::Packet::parse(&json, crate::document::Format::Json, json.len())
                .unwrap();
        let expected = expected
            .layers
            .iter_mut()
            .find(|layer| layer.protocol == name)
            .unwrap();
        if protocol == BuiltinProtocol::ModbusTcp {
            expected.fields.insert("form".into(), "request".into());
            expected.fields.insert("quantity".into(), 2_u16.into());
            expected.fields.insert("data".into(), Bytes::new().into());
        }
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
        for event in &out {
            let message = complete_message(event, protocol, &bytes, &[1]);
            assert_packet_fields(message, expected);
        }

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
                if number == 1 {
                    assert!(out.is_empty(), "{name}, split {split}: {out:?}");
                }
            }
            assert_eq!(out.len(), 1, "{name}, split {split}");
            let message = complete_message(&out[0], protocol, &bytes, &[1, 2]);
            assert_packet_fields(message, expected);
        }
    }
}

#[test]
fn declared_length_is_rejected_before_large_allocation() {
    let mut framer = Framer::new("opcua_tcp");
    assert!(matches!(
        framer.progress(b"MSGF\xff\xff\xff\x7f", 1024),
        Err(crate::protocol::framing::Error::BufferLimit { limit: 1024 })
    ));
    let mut framer = Framer::new("resp");
    assert!(matches!(
        framer.progress(b"$2147483647\r\n", 1024),
        Err(crate::protocol::framing::Error::BufferLimit { limit: 1024 })
    ));
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
    assert_eq!(events.len(), 1);
    let message = complete_message(&events[0], BuiltinProtocol::Mqtt, b"\xc0\0", &[1]);
    assert_eq!(message.flow.flow.destination_port, 1884);
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
    assert_eq!(events.len(), 2);
    complete_message(
        &events[0],
        BuiltinProtocol::Mqtt,
        b"\x30\x04\0\x01ax",
        &[2, 3],
    );
    complete_message(&events[1], BuiltinProtocol::Mqtt, b"\xc0\0", &[3]);
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
                        timestamp: UNIX_EPOCH + Duration::from_secs(number),
                    })
                    .unwrap(),
            },
            out,
        )
        .unwrap();
}

#[test]
fn review_selected_source_port_is_not_hidden_by_an_unselected_destination() {
    // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html section 3.13 checked 2026-10-25.
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
    assert_eq!(events.len(), 1);
    let message = complete_message(&events[0], BuiltinProtocol::Mqtt, b"\xd0\0", &[1]);
    assert_eq!(message.flow.flow.source_port, 1883);
    assert_eq!(message.flow.flow.destination_port, 44818);
    assert_eq!(
        message
            .packet
            .as_ref()
            .unwrap()
            .get::<crate::protocol::application::mqtt::Mqtt>()
            .unwrap()
            .packet_type,
        13
    );
}

#[test]
fn review_mqtt5_stays_opaque_in_both_directions_until_a_new_generation() {
    // https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html sections 3.1 and 3.15 checked 2026-10-25.
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
        let expected: &[(&[u8], &[u64], bool)] = &[
            (connect5, &[1, 2], false),
            (publish5, &[2], false),
            (b"\x20\x03\0\0\0", &[3], true),
            (b"\xf0\x02\0\0", &[3], true),
            (publish5, &[3], true),
        ];
        for (event, (wire, sources, reverse)) in events.iter().zip(expected) {
            let message = decoded_message(event);
            assert_eq!(message.status, Status::Unsupported);
            assert_eq!(message.protocol, BuiltinProtocol::Mqtt);
            assert!(message.packet.is_none());
            assert!(
                message
                    .error
                    .as_ref()
                    .is_some_and(|error| error.contains("protocol level 5"))
            );
            assert_eq!(message.wire.as_ref(), *wire);
            assert_eq!(
                message
                    .sources
                    .iter()
                    .map(|source| source.number)
                    .collect::<Vec<_>>(),
                *sources
            );
            assert_eq!(
                message.flow,
                if *reverse { flow().reverse() } else { flow() }
            );
        }
        let mut next = b"\x10\x0c\0\x04MQTT\x04\x02\0\x3c\0\0".to_vec();
        next.extend_from_slice(b"\x30\x04\0\x01ax");
        deliver(&mut collector, &tracker, 4, &next, 1, &mut events);
        assert_eq!(events.len(), 7);
        for (event, wire) in events[5..].iter().zip([&next[..14], &next[14..]]) {
            let message = complete_message(event, BuiltinProtocol::Mqtt, wire, &[4]);
            assert_eq!(message.generation, 1);
        }
    }
}

#[test]
fn review_events_before_the_first_delivery_disable_the_generation() {
    for (event, expected_status) in [
        (
            application::Event::Gap {
                flow: flow(),
                stream: 0,
                generation: 0,
            },
            Status::Gap,
        ),
        (
            application::Event::Conflict {
                flow: flow(),
                stream: 0,
                generation: 0,
            },
            Status::Conflict,
        ),
        (
            application::Event::Evicted {
                flow: flow(),
                stream: 0,
                generation: 0,
            },
            Status::Evicted,
        ),
        (
            application::Event::Closed {
                flow: flow(),
                stream: 0,
                generation: 0,
                reset: true,
            },
            Status::Reset,
        ),
    ] {
        let mut collector = Collector::new(
            Limits::default(),
            crate::protocol::builtin::registry(),
            [BuiltinProtocol::Mqtt],
        )
        .unwrap();
        let tracker = Tracker::new(1 << 20, 32).unwrap();
        let mut events = Vec::new();
        collector.event(event, 1, &mut events).unwrap();
        let [Event::Issue(issue)] = events.as_slice() else {
            panic!("expected one issue before any delivery: {events:?}");
        };
        assert_eq!(issue.status, expected_status);
        assert_eq!(issue.number, 1);
        deliver(&mut collector, &tracker, 2, &[0xc0, 0], 0, &mut events);
        assert_eq!(events.len(), 1);
        deliver_on(
            &mut collector,
            &tracker,
            3,
            flow().reverse(),
            &[0xd0, 0],
            0,
            &mut events,
        );
        let reset = expected_status == Status::Reset;
        assert_eq!(events.len(), if reset { 1 } else { 2 });
        if !reset {
            complete_message(&events[1], BuiltinProtocol::Mqtt, b"\xd0\0", &[3]);
        }
        deliver(&mut collector, &tracker, 4, &[0xc0, 0], 1, &mut events);
        let resumed = complete_message(
            events.last().unwrap(),
            BuiltinProtocol::Mqtt,
            b"\xc0\0",
            &[4],
        );
        assert_eq!(resumed.generation, 1);
    }
}

#[test]
fn review_amqp_unsupported_version_keeps_both_directions_opaque() {
    // https://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-transport-v1.0-os.html#section-protocol-header checked 2026-10-25.
    let mut collector = Collector::new(
        Limits::default(),
        crate::protocol::builtin::registry(),
        [BuiltinProtocol::Amqp],
    )
    .unwrap();
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let mut request = flow();
    request.flow.destination_port = 5672;
    let mut events = Vec::new();
    let wire = b"AMQP\0\x01\0\0\0\0\0\x08\x02\0\0\0";
    deliver_on(
        &mut collector,
        &tracker,
        1,
        request.clone(),
        wire,
        0,
        &mut events,
    );
    deliver_on(
        &mut collector,
        &tracker,
        2,
        request.reverse(),
        &wire[8..],
        0,
        &mut events,
    );
    assert_eq!(events.len(), 1);
    let preface = decoded_message(&events[0]);
    assert_eq!(preface.status, Status::Unsupported);
    assert_eq!(preface.wire.as_ref(), &wire[..8]);
    assert!(preface.packet.is_none());
    assert_eq!(
        preface
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>(),
        [1]
    );
    let (tail, summary) = collector.finish(&RunSummary::default()).unwrap();
    assert_eq!(tail.len(), 2);
    for (source_port, source) in [(40000, 1), (5672, 2)] {
        let message = tail
            .iter()
            .map(decoded_message)
            .find(|message| message.flow.flow.source_port == source_port)
            .unwrap();
        assert_eq!(message.status, Status::Unsupported);
        assert_eq!(message.wire.as_ref(), &wire[8..]);
        assert!(message.packet.is_none());
        assert_eq!(
            message
                .sources
                .iter()
                .map(|frame| frame.number)
                .collect::<Vec<_>>(),
            [source]
        );
    }
    assert_eq!(summary.unsupported_messages, 3);
    assert_eq!(summary.malformed_messages, 0);
}

#[test]
fn review_capture_stops_early_conflicts_and_gaps_until_tuple_reuse() {
    use crate::{
        codec::Addresses,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, link::Ethernet, network::Ipv4, transport::Tcp},
    };
    use std::time::Duration;

    for conflict in [true, false] {
        let registry = builtin::registry();
        let builder = crate::build::Builder::new(registry.clone());
        let mut writer = crate::capture_file::Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        let mut segments: Vec<(u64, u32, u16, &[u8])> =
            vec![(0, 100, Tcp::SYN, b""), (1, 103, Tcp::ACK, b"\0\x01ax")];
        if conflict {
            segments.extend([
                (2, 103, Tcp::ACK, b"\0\x01ay" as &[u8]),
                (3, 101, Tcp::ACK, b"\x30\x04" as &[u8]),
            ]);
        } else {
            segments.push((5, 107, Tcp::ACK, b"\xc0\0"));
        }
        let restart = if conflict { 4 } else { 6 };
        segments.extend([
            (restart, 200, Tcp::SYN, b"" as &[u8]),
            (restart + 1, 201, Tcp::ACK, b"\xc0\0" as &[u8]),
        ]);
        let last_frame = segments.len() as u64;
        for (seconds, sequence, flags, payload) in segments {
            let mut packet = Packet::new();
            packet.push(Ethernet::default());
            packet.push(Ipv4 {
                source: "192.0.2.1".parse().unwrap(),
                destination: "192.0.2.2".parse().unwrap(),
                ..Default::default()
            });
            packet.push(Tcp {
                source_port: 40000,
                destination_port: 1883,
                sequence,
                flags,
                ..Default::default()
            });
            if !payload.is_empty() {
                packet.push(Raw::new(Bytes::copy_from_slice(payload)));
            }
            let built = builder
                .build(packet, Addresses::default(), Default::default())
                .unwrap();
            let frame = Frame::new(
                UNIX_EPOCH + Duration::from_secs(seconds),
                LinkType::ETHERNET,
                built.bytes,
            )
            .unwrap();
            writer.write_frame(&frame).unwrap();
        }
        let capture = writer.into_inner();
        let mut reader = crate::capture_file::Reader::new(&capture[..]).unwrap();
        let collector =
            Collector::new(Limits::default(), registry.clone(), [BuiltinProtocol::Mqtt]).unwrap();
        let mut events = Vec::new();
        let options = crate::analysis::Options {
            limits: crate::analysis::Limits {
                tcp: crate::analysis::reassembly::tcp::Limits {
                    idle_expiry: Duration::from_secs(3),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let outcome = crate::analysis::Session::new(registry, options, collector)
            .run(
                &mut reader,
                |_| Ok(()),
                |event| {
                    events.push(event);
                    Ok(())
                },
            )
            .unwrap();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Issue(issue)
            if issue.status == if conflict { Status::Conflict } else { Status::Gap }))
        );
        assert_eq!(outcome.summary.complete_messages, 1, "{events:?}");
        let completed: Vec<_> = events.iter().filter(|event|
            matches!(event, Event::Message(message) if message.status == Status::Complete)).collect();
        assert_eq!(completed.len(), 1);
        let message = complete_message(
            completed[0],
            BuiltinProtocol::Mqtt,
            b"\xc0\0",
            &[last_frame],
        );
        assert_eq!(message.generation, 1);
    }
}

#[test]
fn review_server_first_payload_uses_the_handshake_server_port() {
    use crate::{
        codec::Addresses,
        frame::{Frame, LinkType},
        packet::Packet,
        protocol::{application::bgp::Bgp, builtin, link::Ethernet, network::Ipv4, transport::Tcp},
    };
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut writer = crate::capture_file::Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    for (server, sequence, acknowledgment, flags, payload) in [
        (false, 100, 0, Tcp::SYN, false),
        (true, 900, 101, Tcp::SYN | Tcp::ACK, false),
        (false, 101, 901, Tcp::ACK, false),
        (true, 901, 101, Tcp::ACK, true),
        (false, 101, 930, Tcp::ACK, true),
    ] {
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            source: if server { "192.0.2.2" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            destination: if server { "192.0.2.1" } else { "192.0.2.2" }
                .parse()
                .unwrap(),
            ..Default::default()
        });
        packet.push(Tcp {
            source_port: if server { 179 } else { 44818 },
            destination_port: if server { 44818 } else { 179 },
            sequence,
            acknowledgment,
            flags,
            ..Default::default()
        });
        if payload {
            packet.push(Bgp {
                message_type: 1,
                version: 4,
                my_as: if server { 64513 } else { 64512 },
                hold_time: 90,
                identifier: if server { "192.0.2.2" } else { "192.0.2.1" }
                    .parse()
                    .unwrap(),
                parameters: crate::protocol::Records::default(),
                ..Default::default()
            });
        }
        let built = builder
            .build(packet, Addresses::default(), Default::default())
            .unwrap();
        writer
            .write_frame(&Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap())
            .unwrap();
    }
    let capture = writer.into_inner();
    // Also cover captures that begin at the SYN-ACK rather than the initial SYN.
    for skip_syn in [false, true] {
        let mut reader = crate::capture_file::Reader::new(&capture[..]).unwrap();
        if skip_syn {
            reader.next_frame().unwrap();
        }
        let collector = Collector::new(
            Limits::default(),
            registry.clone(),
            BuiltinProtocol::ALL
                .iter()
                .copied()
                .filter(|p| p.stream_decode()),
        )
        .unwrap();
        let mut events = Vec::new();
        let outcome =
            crate::analysis::Session::new(registry.clone(), Default::default(), collector)
                .run(
                    &mut reader,
                    |_| Ok(()),
                    |event| {
                        events.push(event);
                        Ok(())
                    },
                )
                .unwrap();
        assert_eq!(outcome.summary.complete_messages, 2, "{events:?}");
        assert_eq!(events.len(), 2);
        for (index, (event, server)) in events.iter().zip([true, false]).enumerate() {
            // https://datatracker.ietf.org/doc/html/rfc4271#section-4.2 checked 2026-10-25.
            let mut wire = vec![0xff; 16];
            wire.extend_from_slice(&[
                0,
                29,
                1,
                4,
                252,
                u8::from(server),
                0,
                90,
                192,
                0,
                2,
                if server { 2 } else { 1 },
                0,
            ]);
            let source = 4 + index as u64 - u64::from(skip_syn);
            let message = complete_message(event, BuiltinProtocol::Bgp, &wire, &[source]);
            assert_eq!(
                message.flow.flow.source_port,
                if server { 179 } else { 44818 }
            );
            let bgp = message.packet.as_ref().unwrap().get::<Bgp>().unwrap();
            assert_eq!(bgp.my_as, if server { 64513 } else { 64512 });
            assert_eq!(bgp.hold_time, 90);
            assert_eq!(
                bgp.identifier.to_string(),
                if server { "192.0.2.2" } else { "192.0.2.1" }
            );
        }
    }
}

#[test]
fn review_sip_keepalives_across_deliveries_do_not_disable_messages() {
    let message = b"OPTIONS sip:service SIP/2.0\r\nContent-Length: 0\r\n\r\n";
    let mut bytes = b"\r\n".to_vec();
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(b"\r\n\r\n");
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(b"\r\n");
    for split in 1..bytes.len() {
        let mut collector = Collector::new(
            Limits::default(),
            crate::protocol::builtin::registry(),
            [BuiltinProtocol::Sip],
        )
        .unwrap();
        let tracker = Tracker::new(1 << 20, 32).unwrap();
        let mut f = flow();
        f.flow.destination_port = 5060;
        let mut events = Vec::new();
        deliver_on(
            &mut collector,
            &tracker,
            1,
            f.clone(),
            &bytes[..split],
            0,
            &mut events,
        );
        deliver_on(
            &mut collector,
            &tracker,
            2,
            f,
            &bytes[split..],
            0,
            &mut events,
        );
        assert_eq!(events.len(), 2, "split {split}: {events:?}");
        for (event, start) in events.iter().zip([2, 6 + message.len()]) {
            let expected: Vec<_> = [
                (split > start).then_some(1),
                (split < start + message.len()).then_some(2),
            ]
            .into_iter()
            .flatten()
            .collect();
            let decoded = complete_message(event, BuiltinProtocol::Sip, message, &expected);
            let sip = decoded
                .packet
                .as_ref()
                .unwrap()
                .get::<crate::protocol::application::sip::Sip>()
                .unwrap();
            assert_eq!(sip.start_line.as_ref(), b"OPTIONS sip:service SIP/2.0");
            assert!(sip.body.is_empty());
        }
        assert!(
            collector
                .finish(&RunSummary::default())
                .unwrap()
                .0
                .is_empty()
        );
    }
}

#[test]
fn review_modbus_uses_handshake_roles_and_preserves_ambiguous_pdus() {
    // https://www.modbus.org/file/secure/modbusprotocolspecification.pdf section 6.3 checked 2026-10-25.
    use crate::{
        codec::Addresses,
        frame::{Frame, LinkType},
        packet::Packet,
        protocol::{
            application::modbus_tcp::ModbusTcp, builtin, link::Ethernet, network::Ipv4,
            transport::Tcp,
        },
    };
    let registry = Arc::new(
        builtin::registry_with(|builder| {
            builder
                .bind("tcp", 1502, "modbus_tcp", i32::MAX)
                .map(|_| ())
        })
        .unwrap(),
    );
    for handshake in [true, false] {
        let builder = crate::build::Builder::new(registry.clone());
        let mut writer = crate::capture_file::Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        for (server, sequence, flags, payload) in [
            (false, 100, Tcp::SYN, false),
            (false, 101, Tcp::ACK, true),
            (true, 901, Tcp::ACK, true),
        ] {
            if !handshake && !payload {
                continue;
            }
            let mut packet = Packet::new();
            packet.push(Ethernet::default());
            packet.push(Ipv4 {
                source: if server { "192.0.2.2" } else { "192.0.2.1" }
                    .parse()
                    .unwrap(),
                destination: if server { "192.0.2.1" } else { "192.0.2.2" }
                    .parse()
                    .unwrap(),
                ..Default::default()
            });
            packet.push(Tcp {
                source_port: if server { 1502 } else { 502 },
                destination_port: if server { 502 } else { 1502 },
                sequence,
                flags,
                ..Default::default()
            });
            if payload {
                packet.push(if server {
                    ModbusTcp {
                        transaction_id: 0x1234,
                        unit_id: 7,
                        function: 3,
                        form: "response".into(),
                        data: Bytes::from_static(b"\0\x2a"),
                        ..Default::default()
                    }
                } else {
                    ModbusTcp {
                        transaction_id: 0x1234,
                        unit_id: 7,
                        function: 3,
                        form: "request".into(),
                        address: 9,
                        quantity: 1,
                        ..Default::default()
                    }
                });
            }
            let built = builder
                .build(packet, Addresses::default(), Default::default())
                .unwrap();
            writer
                .write_frame(&Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap())
                .unwrap();
        }
        let capture = writer.into_inner();
        let mut reader = crate::capture_file::Reader::new(&capture[..]).unwrap();
        let collector = Collector::new(
            Limits::default(),
            registry.clone(),
            [BuiltinProtocol::ModbusTcp],
        )
        .unwrap();
        let mut events = Vec::new();
        let outcome =
            crate::analysis::Session::new(registry.clone(), Default::default(), collector)
                .run(
                    &mut reader,
                    |_| Ok(()),
                    |event| {
                        events.push(event);
                        Ok(())
                    },
                )
                .unwrap();
        assert_eq!(outcome.summary.complete_messages, 2, "{events:?}");
        assert_eq!(events.len(), 2);
        for (index, (event, wire)) in events
            .iter()
            .zip([
                b"\x12\x34\0\0\0\x06\x07\x03\0\x09\0\x01".as_slice(),
                b"\x12\x34\0\0\0\x05\x07\x03\x02\0\x2a",
            ])
            .enumerate()
        {
            let message = complete_message(
                event,
                BuiltinProtocol::ModbusTcp,
                wire,
                &[index as u64 + 1 + u64::from(handshake)],
            );
            let pdu = message.packet.as_ref().unwrap().get::<ModbusTcp>().unwrap();
            assert_eq!(
                (pdu.transaction_id, pdu.unit_id, pdu.function),
                (0x1234, 7, 3)
            );
            if !handshake {
                assert_eq!(pdu.form, "raw");
                assert_eq!(pdu.data.as_ref(), &wire[8..]);
            } else if index == 0 {
                assert_eq!(pdu.form, "request");
                assert_eq!((pdu.address, pdu.quantity), (9, 1));
                assert!(pdu.data.is_empty());
            } else {
                assert_eq!(pdu.form, "response");
                assert_eq!(pdu.data.as_ref(), b"\0\x2a");
            }
        }
    }
}

#[test]
fn review_many_coalesced_messages_preserve_the_layer_budget_and_stream() {
    use crate::{
        codec::Addresses,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, link::Ethernet, network::Ipv4, transport::Tcp},
    };
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Tcp {
        destination_port: 1883,
        flags: Tcp::ACK,
        ..Default::default()
    });
    packet.push(Raw::new(Bytes::from(b"\xc0\0".repeat(100))));
    let built = builder
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.bytes.clone()).unwrap();
    for max_layers in [4, 8, 64] {
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                frame.clone(),
                crate::decode::Options {
                    limits: crate::packet::Limits {
                        max_layers,
                        ..Default::default()
                    },
                },
            )
            .unwrap();
        assert!(decoded.packet.len() <= max_layers);
        assert_eq!(decoded.packet.get::<Tcp>().unwrap().destination_port, 1883);
        let raw = decoded.packet.get::<Raw>().unwrap();
        let messages: Vec<_> = decoded
            .packet
            .iter()
            .filter_map(|layer| layer.downcast_ref::<crate::protocol::application::mqtt::Mqtt>())
            .collect();
        if max_layers > 4 {
            assert!(!messages.is_empty());
        }
        // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html section 3.12 checked 2026-10-25.
        assert!(messages.iter().all(|message| message.packet_type == 12));
        let reconstructed = messages
            .iter()
            .flat_map(|_| [0xc0, 0])
            .chain(raw.bytes.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(reconstructed, b"\xc0\0".repeat(100));
        assert_eq!(
            builder
                .build(decoded.packet, Addresses::default(), Default::default())
                .unwrap()
                .bytes,
            built.bytes
        );
    }
    let mut writer = crate::capture_file::Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    writer.write_frame(&frame).unwrap();
    let capture = writer.into_inner();
    let mut reader = crate::capture_file::Reader::new(&capture[..]).unwrap();
    let collector =
        Collector::new(Limits::default(), registry.clone(), [BuiltinProtocol::Mqtt]).unwrap();
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
    assert_eq!(outcome.summary.complete_messages, 100);
    assert_eq!(events.len(), 100);
    for (index, event) in events.iter().enumerate() {
        let message = complete_message(event, BuiltinProtocol::Mqtt, b"\xc0\0", &[1]);
        assert_eq!(message.index, index as u64 + 1);
    }
}

#[test]
fn review_declared_buffer_limits_are_policy_errors_for_every_segmentation() {
    let mut mqtt = vec![0x30, 103, 0, 1, b'a'];
    mqtt.extend_from_slice(&[b'x'; 100]);
    let mut resp = b"$100\r\n".to_vec();
    resp.extend_from_slice(&[b'x'; 100]);
    resp.extend_from_slice(b"\r\n");
    for (protocol, port, header, wire) in [
        (BuiltinProtocol::Mqtt, 1883, 2, mqtt),
        (BuiltinProtocol::Resp, 6379, 6, resp),
    ] {
        for limit in [16, wire.len()] {
            for split in [header, wire.len()] {
                let mut collector = Collector::new(
                    Limits {
                        max_buffer_bytes: limit,
                        ..Default::default()
                    },
                    crate::protocol::builtin::registry(),
                    [protocol],
                )
                .unwrap();
                let tracker = Tracker::new(1 << 20, 32).unwrap();
                let mut f = flow();
                f.flow.destination_port = port;
                let mut events = Vec::new();
                let mut result = Ok(());
                for (index, chunk) in [&wire[..split], &wire[split..]].into_iter().enumerate() {
                    if chunk.is_empty() || result.is_err() {
                        break;
                    }
                    result = collector.data(
                        application::Delivery {
                            flow: f.clone(),
                            stream: 0,
                            generation: 0,
                            bytes: Bytes::copy_from_slice(chunk),
                            sources: tracker
                                .single(SourceFrame {
                                    number: index as u64 + 1,
                                    timestamp: UNIX_EPOCH,
                                })
                                .unwrap(),
                        },
                        &mut events,
                    );
                }
                if limit < wire.len() {
                    assert!(
                        matches!(
                            result,
                            Err(Error::Limit {
                                field: "max_buffer_bytes",
                                limit: 16
                            })
                        ),
                        "{result:?}"
                    );
                    assert!(events.is_empty());
                } else {
                    result.unwrap();
                    assert_eq!(events.len(), 1);
                    let sources: &[u64] = if split == wire.len() { &[1] } else { &[1, 2] };
                    complete_message(&events[0], protocol, &wire, sources);
                    let following = if protocol == BuiltinProtocol::Mqtt {
                        b"\xc0\0".as_slice()
                    } else {
                        b"+OK\r\n"
                    };
                    deliver_on(&mut collector, &tracker, 3, f, following, 0, &mut events);
                    assert_eq!(events.len(), 2);
                    complete_message(&events[1], protocol, following, &[3]);
                }
            }
        }
    }
}
