// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn pipeline_numbers_frames_and_canonicalizes_conversations() {
    let (observed, summary) = observe(&mut two_conversation_capture(), &AnalysisOptions::default());

    // Both directions of the TCP conversation share one index, and frame
    // numbers are capture positions, starting from one.
    assert_eq!(
        observed,
        [
            Observed {
                number: 1,
                tcp_stream: Some(0),
                udp_stream: None,
                tcp_event_count: 0,
                completed_fragment_bytes: None,
            },
            Observed {
                number: 2,
                tcp_stream: None,
                udp_stream: Some(0),
                tcp_event_count: 0,
                completed_fragment_bytes: None,
            },
            Observed {
                number: 3,
                tcp_stream: Some(0),
                udp_stream: None,
                tcp_event_count: 0,
                completed_fragment_bytes: None,
            },
            Observed {
                number: 4,
                tcp_stream: None,
                udp_stream: Some(0),
                tcp_event_count: 0,
                completed_fragment_bytes: None,
            },
        ]
    );
    assert_eq!(summary.frames_read, 4);
    assert_eq!(summary.frames_matched, 4);
    assert_eq!(summary.tcp_stream_count, 1);
    assert_eq!(summary.udp_stream_count, 1);
    assert!(summary.trailing_tcp_events.is_empty());
}

#[test]
fn filter_narrows_dispatch_without_renumbering_or_reindexing() {
    let registry = registry();
    let filter = Filter::compile("tcp", &registry, FilterOptions::default()).unwrap();
    let (observed, summary) = observe(
        &mut two_conversation_capture(),
        &AnalysisOptions {
            filter: Some(&filter),
            ..AnalysisOptions::default()
        },
    );

    // Only the TCP frames are dispatched, but they keep their capture
    // numbers, and the unmatched UDP conversation was still indexed.
    assert_eq!(
        observed
            .iter()
            .map(|record| record.number)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(summary.frames_read, 4);
    assert_eq!(summary.frames_matched, 2);
    assert_eq!(summary.udp_stream_count, 1);
}

#[test]
fn stream_filters_resolve_against_the_assigned_indices() {
    let registry = registry();
    let filter = Filter::compile("tcp.stream == 0", &registry, FilterOptions::default()).unwrap();
    assert!(filter.requirements().stream_index);
    let (observed, _) = observe(
        &mut two_conversation_capture(),
        &AnalysisOptions {
            filter: Some(&filter),
            ..AnalysisOptions::default()
        },
    );
    assert_eq!(
        observed
            .iter()
            .map(|record| record.number)
            .collect::<Vec<_>>(),
        [1, 3]
    );
}

#[test]
fn tcp_reassembly_emits_data_for_matched_frames_and_flushes_residue() {
    let mut reader = capture(vec![
        tcp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 100, b"he"),
        tcp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 102, b"llo"),
    ]);
    let mut data = Vec::new();
    let summary = run(
        &mut reader,
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            for event in record.tcp_events {
                if let SessionTcpEvent::Data { bytes, .. } = event {
                    data.push(bytes.clone());
                }
            }
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(
        data,
        [Bytes::from_static(b"he"), Bytes::from_static(b"llo")]
    );
    // The flow never closed, so ending the run flushes it explicitly.
    assert!(!summary.trailing_tcp_events.is_empty());
}

#[test]
fn tcp_payload_is_exact_wire_bytes_and_excludes_link_padding() {
    // A short Ethernet frame is padded past the IP total length. The decoder
    // represents that as padding outside the network layer, and the segment
    // payload must carry exactly the stream bytes, not the padding.
    let mut packet = Packet::new();
    packet
        .push(packetcraftr_protocol::link::Ethernet::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port: 1000,
            destination_port: 2000,
            sequence: 100,
            flags: Tcp::ACK,
            ..Tcp::default()
        })
        .push(Raw::new(Bytes::from_static(b"hi")));
    let mut bytes = build_bytes(packet).to_vec();
    bytes.extend_from_slice(&[0_u8; 6]);
    let decoded = Decoder::new(registry())
        .decode(
            Frame::new(UNIX_EPOCH, LinkType::ETHERNET, bytes).unwrap(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(
        decoded
            .packet
            .iter()
            .any(|layer| layer.as_any().downcast_ref::<Padding>().is_some()),
        "the fixture must actually decode with a padding layer"
    );
    let segment = tcp_segment(&decoded).unwrap();
    assert_eq!(segment.payload, Bytes::from_static(b"hi"));
}

#[test]
fn a_one_conversation_budget_admits_both_directions_of_that_conversation() {
    // The budget counts conversations, not directional flows: data in both
    // directions of one conversation must fit a one-conversation budget.
    let mut data = Vec::new();
    let summary = run(
        &mut capture(vec![
            tcp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 100, b"ping"),
            tcp_packet([10, 0, 0, 2], 2000, [10, 0, 0, 1], 1000, 500, b"pong"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            limits: AnalysisLimits {
                max_flows: 1,
                ..AnalysisLimits::default()
            },
            ..AnalysisOptions::default()
        },
        |record| {
            for event in record.tcp_events {
                if let SessionTcpEvent::Data { bytes, .. } = event {
                    data.push(bytes.clone());
                }
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        data,
        [Bytes::from_static(b"ping"), Bytes::from_static(b"pong")]
    );
    assert_eq!(summary.tcp_stream_count, 1);
}

#[test]
fn bare_acknowledgments_consume_no_reassembly_state() {
    // Ten distinct flows of payloadless ACKs: indexed as conversations, but
    // none may occupy reassembly state a data-bearing flow would need.
    let packets = (0..10_u8)
        .map(|flow| tcp_packet([10, 0, 0, flow], 1000, [10, 0, 0, 200], 80, 100, b""))
        .collect::<Vec<_>>();
    let summary = run(
        &mut capture(packets),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            assert!(record.tcp_events.is_empty());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.tcp_stream_count, 10);
    assert!(summary.trailing_tcp_events.is_empty());
}

#[test]
fn idle_reassembly_state_expires_on_capture_time() {
    // The second frame arrives far past the idle expiry window, so the
    // first flow's state is evicted before the new flow is pushed, and the
    // eviction evidence rides with the frame that revealed it.
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (seconds, packet) in [
        (
            0,
            tcp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 100, b"he"),
        ),
        (
            600,
            tcp_packet([10, 0, 0, 5], 1000, [10, 0, 0, 6], 2000, 100, b"yo"),
        ),
    ] {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    LinkType::RAW,
                    build_bytes(packet),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let mut evictions = Vec::new();
    let summary = run(
        &mut reader,
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            for event in record.tcp_events {
                if let SessionTcpEvent::Evicted { flow, .. } = event {
                    evictions.push((record.number, flow.source_port));
                }
            }
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(evictions, [(2, 1000)]);
    // Only the second flow was still buffered at the end.
    assert_eq!(summary.trailing_tcp_events.len(), 1);
}

#[test]
fn expiry_is_exact_at_the_boundary_even_between_sweeps() {
    // Flow A idles from t=0. An unrelated push at t=119.9s sweeps (A is not
    // yet expired) and resets the sweep throttle; A's next frame lands at
    // t=120.8s, inside the throttle window but past the 120s idle expiry.
    // The pre-push expiry must still run, so the new segment starts a fresh
    // generation instead of merging into stale state.
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (millis, packet) in [
        (
            0_u64,
            tcp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 100, b"aa"),
        ),
        (
            119_900,
            tcp_packet([10, 0, 0, 5], 1000, [10, 0, 0, 6], 2000, 100, b"xx"),
        ),
        (
            120_800,
            tcp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 5000, b"bb"),
        ),
    ] {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_millis(millis),
                    LinkType::RAW,
                    build_bytes(packet),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let mut boundary_events = Vec::new();
    run(
        &mut Reader::new(Cursor::new(writer.into_inner())).unwrap(),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            if record.number == 3 {
                boundary_events = record.tcp_events.to_vec();
            }
            Ok(())
        },
    )
    .unwrap();

    // The stale generation is evicted first, then the new segment's data
    // flows immediately — a merge into old state would report a gap instead.
    assert!(boundary_events.iter().any(|event| matches!(
        event,
        SessionTcpEvent::Evicted { flow, .. } if flow.source == "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    )));
    assert!(boundary_events.iter().any(|event| matches!(
        event,
        SessionTcpEvent::Data { bytes, .. } if bytes == &Bytes::from_static(b"bb")
    )));
}

#[test]
fn conversations_report_in_assigned_index_order() {
    let mut index = StreamIndex::new();
    // The first-seen flow sorts canonically AFTER the second-seen flow, so a
    // table-order walk would invert them.
    let first = FlowKey {
        source: "10.0.0.9".parse().unwrap(),
        source_port: 1,
        destination: "10.0.0.8".parse().unwrap(),
        destination_port: 1,
    };
    let second = FlowKey {
        source: "10.0.0.1".parse().unwrap(),
        source_port: 1,
        destination: "10.0.0.2".parse().unwrap(),
        destination_port: 1,
    };
    assert_eq!(index.assign(&first, 1, 10).unwrap(), 0);
    assert_eq!(index.assign(&second, 2, 10).unwrap(), 1);
    assert_eq!(
        index
            .conversations()
            .into_iter()
            .map(|(_, stream)| stream)
            .collect::<Vec<_>>(),
        [0, 1]
    );
}

#[test]
fn fragment_reassembly_completes_split_datagrams() {
    let mut reader = capture(vec![
        fragment_packet(0, true, b"01234567"),
        fragment_packet(1, false, b"abcdef"),
    ]);
    let (observed, summary) = observe(&mut reader, &AnalysisOptions::default());
    assert_eq!(observed[0].completed_fragment_bytes, None);
    assert_eq!(observed[1].completed_fragment_bytes, Some(14));
    assert!(summary.trailing_fragment_events.is_empty());
}

#[test]
fn conflicting_reassembly_data_classifies_as_packet_not_budget() {
    // Two fragments claim the same byte range with different content. That
    // is corrupted or hostile capture data, and no budget change fixes it,
    // so it must not classify as a resource limit.
    let error = run(
        &mut capture(vec![
            fragment_packet(0, true, b"01234567"),
            fragment_packet(0, true, b"abcdefgh"),
        ]),
        registry(),
        &AnalysisOptions::default(),
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(error, Error::Fragments { number: 2, .. }));
    assert_eq!(error.classification().code, "packet.reassembly");
    assert_eq!(error.classification().kind, Kind::Packet);
}

#[test]
fn incomplete_fragments_at_end_of_capture_are_surfaced_not_dropped() {
    let mut reader = capture(vec![fragment_packet(0, true, b"01234567")]);
    let (observed, summary) = observe(&mut reader, &AnalysisOptions::default());
    assert_eq!(observed[0].completed_fragment_bytes, None);
    assert!(matches!(
        summary.trailing_fragment_events.as_slice(),
        [FragmentEvent::Expired {
            key,
            received_bytes: 8,
            fragment_count: 1,
        }] if key.identification == 7
    ));
}

#[test]
fn adapters_map_decoded_layers_onto_session_inputs() {
    let registry = registry();
    let decoder = Decoder::new(Arc::clone(&registry));
    let frame = Frame::new(
        UNIX_EPOCH,
        LinkType::RAW,
        build_bytes(tcp_packet(
            [10, 0, 0, 1],
            1000,
            [10, 0, 0, 2],
            2000,
            100,
            b"hi",
        )),
    )
    .unwrap();
    let decoded = decoder.decode(frame, DecodeOptions::default()).unwrap();

    let segment = tcp_segment(&decoded).unwrap();
    assert_eq!(segment.sequence, 100);
    assert_eq!(segment.payload, Bytes::from_static(b"hi"));
    assert_eq!(segment.flow.source_port, 1000);
    assert_eq!(segment.flow.destination_port, 2000);
    assert!(!segment.syn);
    assert!(udp_flow(&decoded).is_none());
    assert!(ip_fragment(&decoded).is_none());

    let frame = Frame::new(
        UNIX_EPOCH,
        LinkType::RAW,
        build_bytes(fragment_packet(1, false, b"abcdef")),
    )
    .unwrap();
    let decoded = decoder.decode(frame, DecodeOptions::default()).unwrap();
    let fragment = ip_fragment(&decoded).unwrap();
    assert_eq!(fragment.key.identification, 7);
    assert_eq!(fragment.key.next_header, 17);
    assert_eq!(fragment.offset, 8);
    assert!(!fragment.more_fragments);
    assert_eq!(fragment.bytes, Bytes::from_static(b"abcdef"));
    // A fragmented payload is never mistaken for a transport header.
    assert!(tcp_segment(&decoded).is_none());
    assert!(udp_flow(&decoded).is_none());
}

#[test]
fn frame_and_flow_budgets_fail_closed_with_frame_attribution() {
    let overflow = run(
        &mut two_conversation_capture(),
        registry(),
        &AnalysisOptions {
            limits: AnalysisLimits {
                max_frames: 2,
                ..AnalysisLimits::default()
            },
            ..AnalysisOptions::default()
        },
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(overflow.number(), Some(3));
    assert_eq!(
        overflow.classification().code,
        "policy.capture_stream_limit"
    );

    // Each transport keeps its own conversation table, so the second TCP
    // conversation is the one that exceeds a one-flow budget.
    let flows = run(
        &mut capture(vec![
            tcp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 100, b"hi"),
            tcp_packet([10, 0, 0, 5], 1000, [10, 0, 0, 6], 2000, 100, b"hi"),
        ]),
        registry(),
        &AnalysisOptions {
            limits: AnalysisLimits {
                max_flows: 1,
                ..AnalysisLimits::default()
            },
            ..AnalysisOptions::default()
        },
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        flows,
        Error::StreamLimit {
            number: 2,
            limit: 1
        }
    ));
    assert_eq!(
        flows.classification().code,
        "policy.analysis_resource_limit"
    );

    // The flow budget also bounds fragment reassembly state, which never
    // reaches a stream index: a second incomplete datagram is one too many.
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (identification, seconds) in [(7_u16, 0_u64), (8, 1)] {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(10, 0, 0, 1),
                destination: Ipv4Addr::new(10, 0, 0, 2),
                identification,
                more_fragments: true,
                protocol: WireValue::Exact(17),
                ..Ipv4::default()
            })
            .push(Raw::new(Bytes::from_static(b"01234567")));
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    LinkType::RAW,
                    build_bytes(packet),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let fragments = run(
        &mut Reader::new(Cursor::new(writer.into_inner())).unwrap(),
        registry(),
        &AnalysisOptions {
            limits: AnalysisLimits {
                max_flows: 1,
                ..AnalysisLimits::default()
            },
            ..AnalysisOptions::default()
        },
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(fragments, Error::Fragments { number: 2, .. }));
    assert_eq!(
        fragments.classification().code,
        "policy.analysis_resource_limit"
    );

    // A frame larger than the per-frame budget is a resource refusal, not a
    // claim that the packet itself is malformed.
    let oversized = run(
        &mut two_conversation_capture(),
        registry(),
        &AnalysisOptions {
            limits: AnalysisLimits {
                max_frame_bytes: 20,
                ..AnalysisLimits::default()
            },
            ..AnalysisOptions::default()
        },
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        oversized,
        Error::Decode {
            number: 1,
            source: packetcraftr_packet::decode::Error::PacketSizeLimit { .. },
        }
    ));
    assert_eq!(
        oversized.classification().code,
        "policy.analysis_resource_limit"
    );

    let invalid = AnalysisLimits {
        max_bytes: 0,
        ..AnalysisLimits::default()
    }
    .validate()
    .unwrap_err();
    assert_eq!(invalid.classification().code, "cli.analysis_limit");
}

#[test]
fn stats_collector_tallies_every_table_with_stable_orders() {
    let mut collector = stats::StatsCollector::new(Duration::from_secs(1)).unwrap();
    let summary = run(
        &mut two_conversation_capture(),
        registry(),
        &AnalysisOptions::default(),
        |record| {
            collector.observe(&record);
            Ok(())
        },
    )
    .unwrap();
    let report = collector.finish();

    assert_eq!(report.frames, summary.frames_matched);
    assert_eq!(report.bytes, summary.bytes_read);

    // Conversations: one TCP, one UDP, keyed by their assigned indices.
    // Both directions of the TCP conversation fold into one row under
    // canonical endpoint order.
    assert_eq!(report.conversations.len(), 2);
    let tcp = &report.conversations[0];
    assert_eq!(tcp.transport, stats::TransportKind::Tcp);
    assert_eq!(tcp.stream, 0);
    assert_eq!(
        tcp.address_a,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!((tcp.port_a, tcp.port_b), (1000, 2000));
    assert_eq!((tcp.frames_a_to_b, tcp.frames_b_to_a), (1, 1));
    assert_eq!(tcp.duration(), Duration::from_secs(2));
    let udp = &report.conversations[1];
    assert_eq!(udp.transport, stats::TransportKind::Udp);
    assert_eq!((udp.frames_a_to_b + udp.frames_b_to_a), 2);

    // Protocols: every frame is ipv4, so it leads; both transports follow.
    assert_eq!(report.protocols[0].protocol, "ipv4");
    assert_eq!(report.protocols[0].frames, 4);
    assert!(
        report
            .protocols
            .iter()
            .any(|row| row.protocol == "tcp" && row.frames == 2)
    );

    // Endpoints: four distinct addresses, sorted; 10.0.0.1 sent one frame
    // and received one.
    assert_eq!(report.endpoints.len(), 4);
    let first = &report.endpoints[0];
    assert_eq!(
        first.address,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!((first.tx_frames, first.rx_frames), (1, 1));

    // Ports: tcp 1000, tcp 2000, and udp 53 once even though it is both
    // source and destination.
    assert_eq!(
        report
            .ports
            .iter()
            .map(|row| (row.transport, row.port, row.frames))
            .collect::<Vec<_>>(),
        [
            (stats::TransportKind::Tcp, 1000, 2),
            (stats::TransportKind::Tcp, 2000, 2),
            (stats::TransportKind::Udp, 5353, 2),
        ]
    );

    // I/O: the four frames sit in four one-second buckets.
    assert_eq!(report.io.len(), 4);
    assert_eq!(report.io[0].offset, Duration::ZERO);
    assert_eq!(report.io[3].offset, Duration::from_secs(3));
    assert!(report.io.iter().all(|bucket| bucket.frames == 1));

    assert!(matches!(
        stats::StatsCollector::new(Duration::ZERO),
        Err(Error::InvalidLimit {
            field: "interval",
            ..
        })
    ));
}
