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
        scope: Interner::default().intern(None, vec![]).unwrap(),
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
        .data(delivery(tracker, number, bytes, generation), out)
        .unwrap();
}

fn delivery(
    tracker: &Tracker,
    number: u64,
    bytes: &[u8],
    generation: u64,
) -> application::Delivery {
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
    }
}

#[test]
fn rejected_admission_preserves_bytes_and_sources() {
    for source_limit in [false, true] {
        for resume in [false, true] {
            let limits = Limits {
                max_buffer_bytes: 8,
                max_source_spans: if source_limit { 1 } else { 8 },
                ..Limits::default()
            };
            let mut collector = Collector::new(
                limits,
                crate::protocol::builtin::registry(),
                [BuiltinProtocol::Mqtt],
            )
            .unwrap();
            let tracker = Tracker::new(1 << 20, 32).unwrap();
            let mut events = Vec::new();
            deliver(&mut collector, &tracker, 1, &[0x30, 4], 0, &mut events);
            let rejected = if source_limit {
                &[0u8][..]
            } else {
                &[0u8; 7][..]
            };
            let error = collector
                .data(delivery(&tracker, 2, rejected, 0), &mut events)
                .unwrap_err();
            let field = if source_limit {
                "max_source_spans"
            } else {
                "max_buffer_bytes"
            };
            assert!(matches!(error, Error::Limit { field: actual, .. } if actual == field));

            if resume {
                deliver(
                    &mut collector,
                    &tracker,
                    1,
                    &[0, 1, b'a', b'x'],
                    0,
                    &mut events,
                );
            }
            let (tail, _) = collector.finish(&RunSummary::default()).unwrap();
            events.extend(tail);
            let [Event::Message(message)] = events.as_slice() else {
                panic!("expected one message");
            };
            assert_eq!(
                message.wire.as_ref(),
                if resume {
                    &[0x30, 4, 0, 1, b'a', b'x'][..]
                } else {
                    &[0x30, 4][..]
                }
            );
            assert_eq!(
                message.status,
                if resume {
                    Status::Complete
                } else {
                    Status::Incomplete
                }
            );
            assert_eq!(
                message
                    .sources
                    .iter()
                    .map(|source| source.number)
                    .collect::<Vec<_>>(),
                [1]
            );
        }
    }
}

#[test]
fn framing_limit_preserves_received_bytes() {
    let mut collector = Collector::new(
        Limits {
            max_buffer_bytes: 8,
            ..Limits::default()
        },
        crate::protocol::builtin::registry(),
        [BuiltinProtocol::Mqtt],
    )
    .unwrap();
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let mut events = Vec::new();
    deliver(&mut collector, &tracker, 1, &[0x30], 0, &mut events);
    let error = collector
        .data(delivery(&tracker, 2, &[0x10], 0), &mut events)
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Limit {
            field: "max_buffer_bytes",
            ..
        }
    ));
    let (tail, _) = collector.finish(&RunSummary::default()).unwrap();
    let [Event::Message(message)] = tail.as_slice() else {
        panic!("expected one message")
    };
    assert_eq!(message.wire.as_ref(), &[0x30, 0x10]);
    assert_eq!(message.status, Status::Incomplete);
    assert_eq!(
        message
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>(),
        [1, 2]
    );
}

#[test]
fn provenance_failure_preserves_received_bytes() {
    let source_charge = 256 + std::mem::size_of::<SourceFrame>();
    let tracker = Tracker::new(2048 + 512 + 3 * source_charge - 1, 32).unwrap();
    let data = delivery(&tracker, 1, &[0xc0, 0], 0);
    let blocker = tracker
        .single(SourceFrame {
            number: 2,
            timestamp: UNIX_EPOCH,
        })
        .unwrap();
    let mut collector = Collector::new(
        Limits::default(),
        crate::protocol::builtin::registry(),
        [BuiltinProtocol::Mqtt],
    )
    .unwrap();
    let error = collector.data(data, &mut Vec::new()).unwrap_err();
    assert!(matches!(
        error,
        Error::Provenance(crate::analysis::provenance::Error::Limit { .. })
    ));
    drop(blocker);
    let (tail, _) = collector.finish(&RunSummary::default()).unwrap();
    let [Event::Message(message)] = tail.as_slice() else {
        panic!("expected one message")
    };
    assert_eq!(message.wire.as_ref(), &[0xc0, 0]);
    assert_eq!(message.status, Status::Incomplete);
    assert_eq!(
        message
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>(),
        [1]
    );
}
#[test]
fn mqtt_framing_preserves_sources() {
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
            generation: 0,
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
fn tcp_protocols_accept_split_and_coalesced_frames() {
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
        let port = protocol.tcp_ports()[0];
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
fn oversized_length_rejected_before_allocation() {
    let mut framer = Framer::new(crate::codec::Framing::OpcuaTcp, "opcua_tcp");
    assert!(framer.progress(b"MSGF\xff\xff\xff\x7f", 1024).is_err());
    let mut framer = Framer::new(crate::codec::Framing::Resp, "resp");
    assert!(framer.progress(b"$2147483647\r\n", 1024).is_err());
}

#[test]
fn port_overrides_drive_stream_selection() {
    let registry = crate::protocol::builtin::registry_with(|builder| {
        builder
            .replace_binding("tcp", 1884, "mqtt", crate::registry::Priority::Primary)
            .map(|_| ())
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
fn capture_reassembles_and_attributes_messages() {
    let registry = crate::protocol::builtin::registry();
    let collector =
        Collector::new(Limits::default(), registry.clone(), [BuiltinProtocol::Mqtt]).unwrap();
    let capture = include_bytes!("../../../../../examples/captures/protocol-mqtt-stream.pcap");
    let mut reader =
        crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
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
fn unselected_destination_preserves_source_selection() {
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
fn mqtt5_stays_opaque_until_generation_changes() {
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

#[test]
fn early_events_disable_generation() {
    for event in [
        application::Event::Gap {
            flow: flow(),
            stream: 0,
            generation: 0,
        },
        application::Event::Conflict {
            flow: flow(),
            stream: 0,
            generation: 0,
        },
        application::Event::Evicted {
            flow: flow(),
            stream: 0,
            generation: 0,
        },
        application::Event::Closed {
            flow: flow(),
            stream: 0,
            generation: 0,
            reset: true,
        },
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
        deliver(&mut collector, &tracker, 2, &[0xc0, 0], 0, &mut events);
        assert!(
            events
                .iter()
                .all(|event| !matches!(event, Event::Message(_)))
        );
        deliver_on(
            &mut collector,
            &tracker,
            3,
            flow().reverse(),
            &[0xd0, 0],
            0,
            &mut events,
        );
        // A reset disables both directions, while other events affect just one.
        let reset = matches!(&events[0], Event::Issue(issue) if issue.status == Status::Reset);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::Message(_)))
                .count(),
            usize::from(!reset)
        );
        deliver(&mut collector, &tracker, 4, &[0xc0, 0], 1, &mut events);
        assert!(
            matches!(events.last(), Some(Event::Message(message)) if message.status == Status::Complete && message.generation == 1)
        );
    }
}

#[test]
fn unsupported_amqp_stays_opaque() {
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
    assert!(events.iter().all(
        |event| matches!(event, Event::Message(message) if message.status == Status::Unsupported)
    ));
    let (tail, summary) = collector.finish(&RunSummary::default()).unwrap();
    assert!(tail.iter().all(
        |event| matches!(event, Event::Message(message) if message.status == Status::Unsupported)
    ));
    assert_eq!(summary.unsupported_messages, 3);
    assert_eq!(summary.malformed_messages, 0);
}

#[test]
fn capture_faults_disable_until_tuple_reuse() {
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
        let mut writer = crate::capture_file::Writer::pcap_with_options(
            Vec::new(),
            LinkType::ETHERNET,
            Default::default(),
        )
        .unwrap();
        let mut segments: Vec<(u64, u32, u16, &[u8])> =
            vec![(0, 100, Tcp::SYN, b""), (1, 103, Tcp::ACK, b"\0\x01ax")];
        if conflict {
            segments.extend([
                (2, 103, Tcp::ACK, b"\0\x01ay" as &[u8]),
                (3, 101, Tcp::ACK, b"\x30\x04" as &[u8]),
            ]);
        } else {
            segments.push((122, 107, Tcp::ACK, b"\xc0\0"));
        }
        segments.extend([
            (123, 200, Tcp::SYN, b"" as &[u8]),
            (124, 201, Tcp::ACK, b"\xc0\0" as &[u8]),
        ]);
        for (seconds, sequence, flags, payload) in segments {
            let mut packet = Packet::default();
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
                Some(UNIX_EPOCH + Duration::from_secs(seconds)),
                LinkType::ETHERNET,
                built.bytes,
            )
            .unwrap();
            writer.write_frame(&frame).unwrap();
        }
        let capture = writer.into_inner();
        let mut reader =
            crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
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
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Issue(issue)
            if issue.status == if conflict { Status::Conflict } else { Status::Gap }))
        );
        assert_eq!(outcome.summary.complete_messages, 1, "{events:?}");
        assert!(events.iter().any(|event| matches!(event, Event::Message(message)
            if message.status == Status::Complete && message.generation == 1 && message.wire.as_ref() == b"\xc0\0")));
    }
}

#[test]
fn server_first_payload_uses_handshake_port() {
    use crate::{
        codec::Addresses,
        frame::{Frame, LinkType},
        packet::Packet,
        protocol::{application::bgp::Bgp, builtin, link::Ethernet, network::Ipv4, transport::Tcp},
    };
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut writer = crate::capture_file::Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        Default::default(),
    )
    .unwrap();
    for (server, sequence, acknowledgment, flags, payload) in [
        (false, 100, 0, Tcp::SYN, false),
        (true, 900, 101, Tcp::SYN | Tcp::ACK, false),
        (false, 101, 901, Tcp::ACK, false),
        (true, 901, 101, Tcp::ACK, true),
        (false, 101, 930, Tcp::ACK, true),
    ] {
        let mut packet = Packet::default();
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
                my_as: 64512,
                identifier: "192.0.2.1".parse().unwrap(),
                ..Default::default()
            });
        }
        let built = builder
            .build(packet, Addresses::default(), Default::default())
            .unwrap();
        writer
            .write_frame(&Frame::new(Some(UNIX_EPOCH), LinkType::ETHERNET, built.bytes).unwrap())
            .unwrap();
    }
    let capture = writer.into_inner();
    // Also cover captures that begin at the SYN-ACK rather than the initial SYN.
    for skip_syn in [false, true] {
        let mut reader =
            crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
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
        assert!(
            events
                .iter()
                .all(|event| matches!(event, Event::Message(message)
            if message.status == Status::Complete && message.protocol == BuiltinProtocol::Bgp))
        );
    }
}

#[test]
fn split_sip_keepalives_preserve_messages() {
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
            let Event::Message(decoded) = event else {
                panic!("unexpected issue");
            };
            assert_eq!(decoded.status, Status::Complete);
            assert_eq!(decoded.wire.as_ref(), message);
            let expected: Vec<_> = [
                (split > start).then_some(1),
                (split < start + message.len()).then_some(2),
            ]
            .into_iter()
            .flatten()
            .collect();
            assert_eq!(
                decoded
                    .sources
                    .iter()
                    .map(|source| source.number)
                    .collect::<Vec<_>>(),
                expected
            );
        }
        assert_eq!(collector.buffered, 0);
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
fn modbus_preserves_roles_and_ambiguous_pdus() {
    use crate::{
        codec::Addresses,
        frame::{Frame, LinkType},
        packet::Packet,
        protocol::{
            application::modbus_tcp::{ModbusTcp, PduForm},
            builtin,
            link::Ethernet,
            network::Ipv4,
            transport::Tcp,
        },
    };
    let registry = Arc::new(
        builtin::registry_with(|builder| {
            builder
                .replace_binding(
                    "tcp",
                    1502,
                    "modbus_tcp",
                    crate::registry::Priority::Primary,
                )
                .map(|_| ())
        })
        .unwrap(),
    );
    for handshake in [true, false] {
        let builder = crate::build::Builder::new(registry.clone());
        let mut writer = crate::capture_file::Writer::pcap_with_options(
            Vec::new(),
            LinkType::ETHERNET,
            Default::default(),
        )
        .unwrap();
        for (server, sequence, flags, payload) in [
            (false, 100, Tcp::SYN, false),
            (false, 101, Tcp::ACK, true),
            (true, 901, Tcp::ACK, true),
        ] {
            if !handshake && !payload {
                continue;
            }
            let mut packet = Packet::default();
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
                        form: PduForm::Response,
                        data: Bytes::from_static(b"\0\x2a"),
                        ..Default::default()
                    }
                } else {
                    ModbusTcp::default()
                });
            }
            let built = builder
                .build(packet, Addresses::default(), Default::default())
                .unwrap();
            writer
                .write_frame(
                    &Frame::new(Some(UNIX_EPOCH), LinkType::ETHERNET, built.bytes).unwrap(),
                )
                .unwrap();
        }
        let capture = writer.into_inner();
        let mut reader =
            crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
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
        let forms: Vec<_> = events
            .iter()
            .map(|event| {
                let Event::Message(message) = event else {
                    panic!("unexpected event");
                };
                message
                    .packet
                    .as_ref()
                    .unwrap()
                    .get::<ModbusTcp>()
                    .unwrap()
                    .form
                    .as_str()
            })
            .collect();
        assert_eq!(
            forms,
            if handshake {
                ["request", "response"]
            } else {
                ["raw", "raw"]
            }
        );
    }
}

#[test]
fn coalesced_messages_preserve_budget_and_stream() {
    use crate::{
        codec::Addresses,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, link::Ethernet, network::Ipv4, transport::Tcp},
    };
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut packet = Packet::default();
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
    let frame = Frame::new(Some(UNIX_EPOCH), LinkType::ETHERNET, built.bytes.clone()).unwrap();
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
        assert_eq!(decoded.packet.len(), max_layers);
        assert!(decoded.packet.get::<Raw>().is_some());
        assert_eq!(
            builder
                .build(decoded.packet, Addresses::default(), Default::default())
                .unwrap()
                .bytes,
            built.bytes
        );
    }
    let mut writer = crate::capture_file::Writer::pcap_with_options(
        Vec::new(),
        LinkType::ETHERNET,
        Default::default(),
    )
    .unwrap();
    writer.write_frame(&frame).unwrap();
    let capture = writer.into_inner();
    let mut reader =
        crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
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
    assert!(events.iter().all(
        |event| matches!(event, Event::Message(message) if message.status == Status::Complete)
    ));
}

#[test]
fn segmentation_preserves_buffer_policy_errors() {
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
                    assert!(
                        matches!(events.as_slice(), [Event::Message(message)] if message.status == Status::Complete)
                    );
                }
            }
        }
    }
}

#[test]
fn receive_buffers_reuse_capacity_without_loss() {
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let mut collector = Collector::new(
        Limits {
            max_buffer_bytes: 16,
            ..Limits::default()
        },
        crate::protocol::builtin::registry(),
        [BuiltinProtocol::Mqtt],
    )
    .unwrap();
    let mut output = Vec::new();
    BUFFER_STATS.with(|stats| stats.set((0, 0, 0)));
    deliver(
        &mut collector,
        &tracker,
        1,
        &[0xc0, 0, 0x30, 4],
        0,
        &mut output,
    );
    for number in 2..=101 {
        deliver(
            &mut collector,
            &tracker,
            number,
            &[0, 1, b'a', b'x', 0xc0, 0, 0x30, 4],
            0,
            &mut output,
        );
    }
    let mut direction = collector.directions.remove(&flow()).unwrap();
    collector
        .flush(
            &flow(),
            &mut direction,
            Status::Incomplete,
            None,
            &mut output,
        )
        .unwrap();
    let messages: Vec<_> = output
        .iter()
        .map(|event| match event {
            Event::Message(message) => message,
            Event::Issue(_) => panic!("unexpected issue"),
        })
        .collect();
    assert_eq!(messages.len(), 202);
    assert_eq!(messages[0].wire.as_ref(), &[0xc0, 0]);
    for (index, pair) in messages[1..201].as_chunks::<2>().0.iter().enumerate() {
        assert_eq!(pair[0].wire.as_ref(), &[0x30, 4, 0, 1, b'a', b'x']);
        assert_eq!(pair[0].status, Status::Complete);
        assert_eq!(
            pair[0]
                .sources
                .iter()
                .map(|frame| frame.number)
                .collect::<Vec<_>>(),
            vec![index as u64 + 1, index as u64 + 2]
        );
        assert_eq!(pair[1].wire.as_ref(), &[0xc0, 0]);
    }
    assert_eq!(messages[201].wire.as_ref(), &[0x30, 4]);
    assert_eq!(messages[201].status, Status::Incomplete);
    let (allocations, copied, peak) = BUFFER_STATS.with(std::cell::Cell::get);
    assert!(allocations <= 2, "{allocations} receive-buffer allocations");
    assert!(copied <= 202, "{copied} suffix bytes copied");
    assert!(
        peak <= 16,
        "{peak} allocated bytes exceed the configured limit"
    );
}

#[test]
fn directions_share_reclaimed_capacity() {
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let mut collector = Collector::new(
        Limits {
            max_buffer_bytes: 16,
            ..Limits::default()
        },
        crate::protocol::builtin::registry(),
        [BuiltinProtocol::Mqtt],
    )
    .unwrap();
    let mut output = Vec::new();
    BUFFER_STATS.with(|stats| stats.set((0, 0, 0)));
    for number in 1..=64u64 {
        let mut direction = flow();
        direction.flow.source_port += number as u16;
        collector
            .data(
                application::Delivery {
                    flow: direction,
                    stream: number,
                    generation: 0,
                    bytes: Bytes::from_static(&[0xc0, 0, 0xc0, 0, 0xc0, 0, 0xc0, 0]),
                    sources: tracker
                        .single(SourceFrame {
                            number,
                            timestamp: UNIX_EPOCH,
                        })
                        .unwrap(),
                },
                &mut output,
            )
            .unwrap();
    }
    assert_eq!(output.len(), 256);
    assert!(output.iter().all(|event| matches!(event, Event::Message(message) if message.status == Status::Complete && message.wire.as_ref() == [0xc0, 0])));
    let (_, _, peak) = BUFFER_STATS.with(std::cell::Cell::get);
    assert!(
        peak <= 16,
        "{peak} allocated bytes exceed the configured limit"
    );
}
