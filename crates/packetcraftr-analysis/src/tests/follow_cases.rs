// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn follow_extracts_both_directions_in_delivery_order() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // Frame 3 arrives out of order and is delivered by frame 4, which fills
    // the hole before it; per-direction bytes still concatenate in stream
    // order.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"ping!"),
            tcp_flags_packet(B, 2000, A, 1000, 500, 105, Tcp::ACK, 512, b"pong!"),
            tcp_flags_packet(A, 1000, B, 2000, 110, 505, Tcp::ACK, 512, b"late!"),
            tcp_flags_packet(A, 1000, B, 2000, 105, 505, Tcp::ACK, 512, b"more!"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    let direction_bytes = |direction: follow::Direction| {
        chunks
            .iter()
            .filter(|chunk| chunk.direction == direction)
            .flat_map(|chunk| chunk.bytes.as_ref())
            .copied()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        direction_bytes(follow::Direction::ClientToServer),
        b"ping!more!late!",
        "{chunks:?}"
    );
    assert_eq!(
        direction_bytes(follow::Direction::ServerToClient),
        b"pong!",
        "{chunks:?}"
    );
    // The out-of-order bytes carry the number of the frame that delivered
    // them.
    assert!(
        chunks
            .iter()
            .filter(|chunk| chunk.direction == follow::Direction::ClientToServer)
            .skip(1)
            .all(|chunk| chunk.number == 4),
        "{chunks:?}"
    );
    assert_eq!(
        summary.client_flow.as_ref().map(|flow| flow.source_port),
        Some(1000)
    );
    assert_eq!(summary.frames, 4);
    assert_eq!(summary.client_bytes, 15);
    assert_eq!(summary.server_bytes, 5);
    assert_eq!(summary.undelivered_bytes, 0);
}

#[test]
fn follow_does_not_duplicate_a_retransmitted_closing_segment() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // The reassembler forgets the cleanly closed flow, so the retransmitted
    // closing segment re-delivers from a fresh generation; extraction must
    // stay exactly-once.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK | Tcp::FIN, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK | Tcp::FIN, 512, b"data"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(chunks.len(), 1, "{chunks:?}");
    assert_eq!(chunks[0].bytes.as_ref(), b"data");
    assert_eq!(summary.client_bytes, 4);
}

#[test]
fn follow_starts_a_fresh_delivery_edge_for_a_reused_tuple() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // The new generation's ISN sits serially before the old delivery edge;
    // its payload is new data, not a re-delivery.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"old!"),
            tcp_syn_packet(A, 1000, B, 2000, 50, None, 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 51, 0, Tcp::ACK, 512, b"new!"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.bytes.as_ref())
            .collect::<Vec<_>>(),
        [b"old!".as_slice(), b"new!".as_slice()],
        "{chunks:?}"
    );
    assert_eq!(summary.client_bytes, 8);
}

#[test]
fn follow_counts_bytes_a_reset_discarded() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // 108..112 is buffered behind a hole when the sender resets; those
    // bytes were captured but never deliverable.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 108, 0, Tcp::ACK, 512, b"late"),
            tcp_flags_packet(A, 1000, B, 2000, 104, 0, Tcp::RST, 0, b""),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(chunks.len(), 1, "{chunks:?}");
    assert_eq!(summary.undelivered_bytes, 4);
}

#[test]
fn a_retransmitted_syn_ack_keeps_follow_deduplication_armed() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // Frame 4 is a delayed duplicate of the handshake, not a new
    // generation: it must not clear the delivery edges, or frame 5's
    // re-delivered close would duplicate the payload.
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            tcp_flags_packet(
                A,
                1000,
                B,
                2000,
                100,
                500,
                Tcp::ACK | Tcp::FIN,
                512,
                b"data",
            ),
            tcp_syn_packet(B, 2000, A, 1000, 499, Some(100), 512, None),
            tcp_flags_packet(
                A,
                1000,
                B,
                2000,
                100,
                500,
                Tcp::ACK | Tcp::FIN,
                512,
                b"data",
            ),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(chunks.len(), 1, "{chunks:?}");
    assert_eq!(chunks[0].bytes.as_ref(), b"data");
    assert_eq!(summary.client_bytes, 4);
}

#[test]
fn follow_survives_same_isn_tuple_reuse() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // Frame 3 reuses the tuple with the very same ISN after payload flowed;
    // the eviction it triggers ends the old generation, and frame 4's bytes
    // are new data even though they reuse the old sequence range.
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"old!"),
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"new!"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.bytes.as_ref())
            .collect::<Vec<_>>(),
        [b"old!".as_slice(), b"new!".as_slice()],
        "{chunks:?}"
    );
    assert_eq!(summary.client_bytes, 8);
}

#[test]
fn follow_dedup_clears_when_a_closed_tuple_is_reused_with_the_same_isn() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // The old connection closed cleanly; the new one reuses tuple and ISN,
    // so its SYN lands on the recorded base — the close is what proves it
    // is a new connection whose bytes are fresh.
    let pipeline = run(
        &mut capture(vec![
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK | Tcp::FIN, 512, b"old!"),
            tcp_syn_packet(A, 1000, B, 2000, 99, None, 512, None),
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"new!"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(
        chunks
            .iter()
            .map(|chunk| chunk.bytes.as_ref())
            .collect::<Vec<_>>(),
        [b"old!".as_slice(), b"new!".as_slice()],
        "{chunks:?}"
    );
    assert_eq!(summary.client_bytes, 8);
}

#[test]
fn follow_counts_pending_bytes_a_new_generation_discarded() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // 108..112 was still buffered behind a hole when the tuple was reused;
    // those captured bytes became undeliverable at that moment.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 108, 0, Tcp::ACK, 512, b"late"),
            tcp_syn_packet(A, 1000, B, 2000, 4999, None, 512, None),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(chunks.len(), 1, "{chunks:?}");
    assert_eq!(summary.undelivered_bytes, 4);
}

#[test]
fn a_delayed_pre_reset_duplicate_is_not_re_emitted() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    // The reset retires the flow, so the delayed duplicate of frame 1
    // re-delivers from a fresh generation; the delivery edge survives the
    // reset and keeps extraction exactly-once.
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 104, 0, Tcp::RST, 0, b""),
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(chunks.len(), 1, "{chunks:?}");
    assert_eq!(chunks[0].bytes.as_ref(), b"data");
    assert_eq!(summary.client_bytes, 4);
}

#[test]
fn follow_keeps_empty_udp_datagrams_as_chunks() {
    const A: [u8; 4] = [10, 0, 0, 1];
    let mut empty = Packet::new();
    empty
        .push(Ipv4 {
            source: Ipv4Addr::from(A),
            destination: Ipv4Addr::new(10, 0, 0, 9),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 53,
            destination_port: 53,
            ..Udp::default()
        });
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Udp,
        index: 0,
    });
    run(
        &mut capture(vec![empty]),
        registry(),
        &AnalysisOptions::default(),
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();

    // The empty datagram is still part of the conversation's shape.
    assert_eq!(chunks.len(), 1, "{chunks:?}");
    assert!(chunks[0].bytes.is_empty());
    assert_eq!(chunks[0].number, 1);
}

#[test]
fn follow_never_emits_reset_payload_as_stream_data() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            tcp_flags_packet(A, 1000, B, 2000, 104, 0, Tcp::RST, 0, b"denied"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(chunks.len(), 1, "{chunks:?}");
    assert_eq!(chunks[0].bytes.as_ref(), b"data");
    assert_eq!(summary.client_bytes, 4);
}

#[test]
fn follow_reports_bytes_stranded_behind_a_missing_segment() {
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Tcp,
        index: 0,
    });
    let pipeline = run(
        &mut capture(vec![
            tcp_flags_packet(A, 1000, B, 2000, 100, 0, Tcp::ACK, 512, b"data"),
            // 104..108 never arrives, so these bytes stay undeliverable.
            tcp_flags_packet(A, 1000, B, 2000, 108, 0, Tcp::ACK, 512, b"late"),
        ]),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    assert_eq!(chunks.len(), 1, "{chunks:?}");
    assert_eq!(chunks[0].bytes.as_ref(), b"data");
    assert_eq!(summary.undelivered_bytes, 4);
}

#[test]
fn follow_selects_one_conversation_and_supports_udp() {
    let mut chunks = Vec::new();
    let mut collector = follow::FollowCollector::new(follow::Selector {
        transport: expert::StreamTransport::Udp,
        index: 0,
    });
    // The run is deliberately unfiltered: frames of the TCP conversation
    // and of a second UDP conversation must contribute nothing.
    let pipeline = run(
        &mut two_conversation_capture(),
        registry(),
        &AnalysisOptions {
            tcp_events: true,
            ..AnalysisOptions::default()
        },
        |record| {
            chunks.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    let summary = collector.finish(&pipeline.trailing_tcp_events);

    // Both frames of udp stream 0 carry the one-byte payload "q" from the
    // same sender, which makes both of them client chunks.
    assert_eq!(chunks.len(), 2, "{chunks:?}");
    assert!(
        chunks.iter().all(|chunk| chunk.bytes.as_ref() == b"q"
            && chunk.direction == follow::Direction::ClientToServer),
        "{chunks:?}"
    );
    assert_eq!(summary.frames, 2);
    assert_eq!(summary.client_bytes, 2);
    assert_eq!(summary.server_bytes, 0);
}
