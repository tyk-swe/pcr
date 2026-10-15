// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::{
    analysis::{self, stats},
    filter::Filter,
    frame::Frame,
};

use crate::common;

fn collect(frames: &[Frame], table: stats::Table, filter: Option<&Filter>) -> stats::Report {
    let mut collector = stats::Collector::for_table(Duration::from_secs(1), table).unwrap();
    let summary = analysis::run(
        &mut common::reader(frames),
        common::registry(),
        &analysis::Options {
            filter,
            ..Default::default()
        },
        |record| {
            collector.observe(&record);
            Ok(())
        },
    )
    .unwrap();
    collector.finish(&summary)
}

#[test]
fn overview_matches_individual_tables_without_collecting_ports_or_io() {
    let registry = common::registry();
    let frames = [
        common::udp_frame(
            &registry,
            UNIX_EPOCH,
            common::CLIENT,
            common::SERVER,
            40_000,
            9,
            b"hello",
        ),
        common::udp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(2),
            common::SERVER,
            common::CLIENT,
            9,
            40_000,
            b"reply",
        ),
        common::tcp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(1),
            common::client_tcp(1, 0, 2, 1024),
            b"",
        ),
    ];
    let overview = collect(&frames, stats::Table::Overview, None);
    assert_eq!(overview.frames, 3);
    assert_eq!(
        overview.bytes,
        frames
            .iter()
            .map(|frame| u64::from(frame.captured_length()))
            .sum::<u64>()
    );
    assert_eq!(
        overview.protocols,
        collect(&frames, stats::Table::Protocols, None).protocols
    );
    assert_eq!(
        overview.endpoints,
        collect(&frames, stats::Table::Endpoints, None).endpoints
    );
    assert_eq!(
        overview.conversations,
        collect(&frames, stats::Table::Conversations, None).conversations
    );
    assert_eq!(overview.protocol_count, overview.protocols.len());
    assert_eq!(overview.endpoint_count, 2);
    assert_eq!(overview.conversation_count, 2);
    assert!(overview.ports.is_empty());
    assert!(overview.io.is_empty());
    assert_eq!(overview.io_origin, None);
    assert_eq!(overview.duration(), Some(Duration::from_secs(2)));
    assert_eq!(overview.packet_rate(), Some(1.5));
}

#[test]
fn overview_respects_filters_and_handles_empty_and_zero_duration() {
    let registry = common::registry();
    let frames = [
        common::udp_frame(
            &registry,
            UNIX_EPOCH,
            common::CLIENT,
            common::SERVER,
            40_000,
            9,
            b"hello",
        ),
        common::udp_frame(
            &registry,
            UNIX_EPOCH,
            common::CLIENT,
            common::SERVER,
            40_001,
            9,
            b"reply",
        ),
    ];
    let filter = Filter::compile("udp.srcport == 40001", &registry, Default::default()).unwrap();
    let report = collect(&frames, stats::Table::Overview, Some(&filter));
    assert_eq!(report.frames, 1);
    assert_eq!(report.conversation_count, 1);
    assert_eq!(report.conversations[0].stream, 1, "index is capture-global");
    assert_eq!(report.duration(), Some(Duration::ZERO));
    assert_eq!(report.packet_rate(), None);
    assert_eq!(report.byte_rate(), None);
    assert!(report.average_packet_size().is_some());
    for empty in [
        collect(&[], stats::Table::Overview, None),
        collect(&frames[..1], stats::Table::Overview, Some(&filter)),
    ] {
        assert_eq!((empty.frames, empty.bytes), (0, 0));
        assert_eq!(
            (
                empty.protocol_count,
                empty.endpoint_count,
                empty.conversation_count
            ),
            (0, 0, 0)
        );
        assert_eq!(empty.duration(), None);
        assert_eq!(empty.average_packet_size(), None);
    }
}
