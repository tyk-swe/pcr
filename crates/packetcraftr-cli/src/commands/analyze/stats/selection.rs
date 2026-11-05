// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;

use packetcraftr_core::{
    analysis::stats::{ConversationStat, Report},
    diagnostic::{Diagnostic, Severity},
};

use super::arguments::Sort;
use super::output::Table;
use crate::rendering::omitted_diagnostic;

fn rank<T>(
    rows: &mut Vec<T>,
    top: Option<usize>,
    sort: Sort,
    volume: impl Fn(&T) -> (u64, u64),
    key: impl Fn(&T, &T) -> Ordering,
) {
    let metric = |row: &T| {
        let (frames, bytes) = volume(row);
        match sort {
            Sort::Frames => (frames, bytes),
            Sort::Bytes => (bytes, frames),
            Sort::Duration => unreachable!("duration sorting is specific to conversations"),
        }
    };
    sort_rows(rows, top, |left, right| {
        metric(right)
            .cmp(&metric(left))
            .then_with(|| key(left, right))
    });
}

fn sort_rows<T>(rows: &mut Vec<T>, top: Option<usize>, compare: impl Fn(&T, &T) -> Ordering) {
    let Some(limit) = top.filter(|limit| *limit < rows.len()) else {
        rows.sort_by(compare);
        return;
    };
    if limit == 0 {
        return;
    }
    let mut indexed = std::mem::take(rows)
        .into_iter()
        .enumerate()
        .collect::<Vec<_>>();
    let compare_indexed = |(left_index, left): &(usize, T), (right_index, right): &(usize, T)| {
        compare(left, right).then_with(|| left_index.cmp(right_index))
    };
    indexed.select_nth_unstable_by(limit, &compare_indexed);
    indexed[..limit].sort_unstable_by(compare_indexed);
    *rows = indexed.into_iter().map(|(_, row)| row).collect();
}

fn conversation_volume(row: &ConversationStat) -> (u64, u64) {
    (
        row.frames_a_to_b.saturating_add(row.frames_b_to_a),
        row.bytes_a_to_b.saturating_add(row.bytes_b_to_a),
    )
}

fn filter_rows<T>(
    rows: &mut Vec<T>,
    minimum: Option<u64>,
    frames: impl Fn(&T) -> u64,
    code: &'static str,
    subject: &str,
) -> Vec<Diagnostic> {
    let Some(minimum) = minimum else {
        return Vec::new();
    };
    let before = rows.len();
    rows.retain(|row| frames(row) >= minimum);
    let omitted = before - rows.len();
    if omitted == 0 {
        return Vec::new();
    }
    vec![Diagnostic::new(
        Severity::Warning,
        code,
        format!(
            "{omitted} {subject} omitted from this document by the --min-frames threshold ({minimum})"
        ),
    )]
}

fn cap<T>(
    rows: &mut Vec<T>,
    top: Option<usize>,
    code: &'static str,
    subject: &str,
) -> Vec<Diagnostic> {
    let Some(limit) = top else { return Vec::new() };
    let omitted = u64::try_from(rows.len().saturating_sub(limit)).unwrap_or(u64::MAX);
    rows.truncate(limit);
    omitted_diagnostic(code, subject, omitted, "--top")
}

pub(super) fn select(
    report: &mut Report,
    table: Table,
    top: Option<usize>,
    sort: Option<Sort>,
    min_frames: Option<u64>,
) -> Vec<Diagnostic> {
    if table == Table::Overview {
        return [Table::Protocols, Table::Endpoints, Table::Conversations]
            .into_iter()
            .flat_map(|table| {
                select(
                    report,
                    table,
                    top,
                    Some(sort.unwrap_or(Sort::Frames)),
                    min_frames,
                )
            })
            .collect();
    }
    let mut diagnostics = match table {
        Table::Conversations => filter_rows(
            &mut report.conversations,
            min_frames,
            |row| conversation_volume(row).0,
            "stats.conversations_filtered",
            "conversation row(s)",
        ),
        Table::Endpoints => filter_rows(
            &mut report.endpoints,
            min_frames,
            |row| row.tx_frames.saturating_add(row.rx_frames),
            "stats.endpoints_filtered",
            "endpoint row(s)",
        ),
        Table::Protocols => filter_rows(
            &mut report.protocols,
            min_frames,
            |row| row.frames,
            "stats.protocols_filtered",
            "protocol row(s)",
        ),
        Table::Ports => filter_rows(
            &mut report.ports,
            min_frames,
            |row| row.frames,
            "stats.ports_filtered",
            "port row(s)",
        ),
        Table::Io => filter_rows(
            &mut report.io,
            min_frames,
            |row| row.frames,
            "stats.io_filtered",
            "io bucket(s)",
        ),
        Table::Fragments => Vec::new(),
        Table::Overview => unreachable!("overview selects its component tables"),
    };
    diagnostics.extend(match table {
        Table::Overview => unreachable!("overview selects its component tables"),
        Table::Conversations => {
            if sort == Some(Sort::Duration) {
                sort_rows(&mut report.conversations, top, |a, b| {
                    b.duration()
                        .cmp(&a.duration())
                        .then_with(|| conversation_volume(b).cmp(&conversation_volume(a)))
                        .then_with(|| (a.transport, a.stream).cmp(&(b.transport, b.stream)))
                });
            } else if let Some(sort) = sort.or_else(|| top.map(|_| Sort::Frames)) {
                rank(
                    &mut report.conversations,
                    top,
                    sort,
                    conversation_volume,
                    |a, b| (a.transport, a.stream).cmp(&(b.transport, b.stream)),
                );
            }
            cap(
                &mut report.conversations,
                top,
                "stats.conversations_omitted",
                "conversation row(s)",
            )
        }
        Table::Endpoints => {
            if let Some(sort) = sort.or_else(|| top.map(|_| Sort::Frames)) {
                rank(
                    &mut report.endpoints,
                    top,
                    sort,
                    |row| {
                        (
                            row.tx_frames.saturating_add(row.rx_frames),
                            row.tx_bytes.saturating_add(row.rx_bytes),
                        )
                    },
                    |a, b| a.address.cmp(&b.address),
                );
            }
            cap(
                &mut report.endpoints,
                top,
                "stats.endpoints_omitted",
                "endpoint row(s)",
            )
        }
        Table::Protocols => {
            if let Some(sort) = sort {
                rank(
                    &mut report.protocols,
                    top,
                    sort,
                    |row| (row.frames, row.bytes),
                    |a, b| a.protocol.cmp(&b.protocol),
                );
            }
            cap(
                &mut report.protocols,
                top,
                "stats.protocols_omitted",
                "protocol row(s)",
            )
        }
        Table::Ports => {
            if let Some(sort) = sort.or_else(|| top.map(|_| Sort::Frames)) {
                rank(
                    &mut report.ports,
                    top,
                    sort,
                    |row| (row.frames, row.bytes),
                    |a, b| (a.transport, a.port).cmp(&(b.transport, b.port)),
                );
            }
            cap(&mut report.ports, top, "stats.ports_omitted", "port row(s)")
        }
        Table::Io => {
            if let Some(sort) = sort {
                rank(
                    &mut report.io,
                    top,
                    sort,
                    |row| (row.frames, row.bytes),
                    |a, b| a.offset.cmp(&b.offset),
                );
            }
            cap(&mut report.io, top, "stats.io_omitted", "io bucket(s)")
        }
        Table::Fragments => Vec::new(),
    });
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::analysis::{
        self, StreamTransport,
        scope::Interner,
        stats::{Collector, EndpointStat, IoBucketStat, PortStat, ProtocolStat},
    };
    use std::time::{Duration, UNIX_EPOCH};

    fn report() -> Report {
        Collector::for_table(Duration::from_secs(1), Default::default())
            .unwrap()
            .finish(&analysis::Summary::default())
    }

    fn conversation(stream: u64, duration: u64, frames: u64, bytes: u64) -> ConversationStat {
        let mut scopes = Interner::default();
        let scope = scopes.intern(None, vec![]).unwrap();
        ConversationStat {
            transport: StreamTransport::Tcp,
            stream,
            scope: scopes.definition(scope).unwrap().clone(),
            address_a: "192.0.2.1".parse().unwrap(),
            port_a: 1000,
            address_b: "192.0.2.2".parse().unwrap(),
            port_b: 443,
            frames_a_to_b: frames / 2,
            frames_b_to_a: frames - frames / 2,
            bytes_a_to_b: bytes,
            bytes_b_to_a: 0,
            first_timestamp: UNIX_EPOCH,
            last_timestamp: UNIX_EPOCH + Duration::from_secs(duration),
        }
    }

    #[test]
    fn duration_ranking_breaks_ties_before_truncation() {
        let mut report = report();
        report.conversations = vec![
            conversation(4, 10, 5, 100),
            conversation(3, 10, 6, 90),
            conversation(2, 10, 6, 100),
            conversation(1, 10, 6, 100),
            conversation(0, 0, 100, 1000),
        ];
        select(
            &mut report,
            Table::Conversations,
            Some(4),
            Some(Sort::Duration),
            None,
        );
        assert_eq!(
            report
                .conversations
                .iter()
                .map(|row| row.stream)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn filtering_preserves_overview_totals() {
        let mut report = report();
        report.frames = 50;
        report.protocol_count = 2;
        report.endpoint_count = 1;
        report.conversation_count = 2;
        report.protocols = vec![
            ProtocolStat {
                protocol: "tcp".into(),
                frames: 10,
                bytes: 100,
            },
            ProtocolStat {
                protocol: "udp".into(),
                frames: 9,
                bytes: 1000,
            },
        ];
        report.endpoints = vec![EndpointStat {
            address: "192.0.2.1".parse().unwrap(),
            tx_frames: 4,
            rx_frames: 6,
            tx_bytes: 40,
            rx_bytes: 60,
        }];
        report.conversations = vec![conversation(0, 10, 9, 1000), conversation(1, 0, 10, 100)];
        let diagnostics = select(
            &mut report,
            Table::Overview,
            Some(1),
            Some(Sort::Bytes),
            Some(10),
        );
        assert_eq!(report.protocols[0].protocol, "tcp");
        assert_eq!(report.conversations[0].stream, 1);
        assert_eq!(report.endpoints.len(), 1);
        assert_eq!(
            (
                report.frames,
                report.protocol_count,
                report.endpoint_count,
                report.conversation_count
            ),
            (50, 2, 1, 2)
        );
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().all(|d| d.code.ends_with("_filtered")));
    }

    #[test]
    fn threshold_and_top_report_separate_omissions() {
        let mut report = report();
        report.protocols = [("tcp", 10), ("udp", 5), ("icmp", 1)]
            .into_iter()
            .map(|(name, frames)| ProtocolStat {
                protocol: name.into(),
                frames,
                bytes: frames * 100,
            })
            .collect();
        let diagnostics = select(
            &mut report,
            Table::Protocols,
            Some(1),
            Some(Sort::Frames),
            Some(5),
        );
        assert_eq!(report.protocols.len(), 1);
        assert_eq!(report.protocols[0].protocol, "tcp");
        assert_eq!(
            diagnostics.iter().map(|d| d.code).collect::<Vec<_>>(),
            vec!["stats.protocols_filtered", "stats.protocols_omitted"]
        );
    }

    #[test]
    fn minimum_frames_filters_ports_and_io() {
        let mut report = report();
        report.ports = vec![PortStat {
            transport: StreamTransport::Tcp,
            port: 80,
            frames: 1,
            bytes: 100,
        }];
        assert!(select(&mut report, Table::Ports, None, None, Some(0)).is_empty());
        assert_eq!(report.ports.len(), 1);
        assert_eq!(
            select(&mut report, Table::Ports, None, None, Some(2)).len(),
            1
        );
        assert!(report.ports.is_empty());
        report.io = vec![IoBucketStat {
            offset: Duration::ZERO,
            frames: 3,
            bytes: 100,
        }];
        select(&mut report, Table::Io, None, None, Some(4));
        assert!(report.io.is_empty());
    }

    fn full_sort_selection(
        report: &mut Report,
        table: Table,
        top: Option<usize>,
        sort: Option<Sort>,
        min_frames: Option<u64>,
    ) -> Vec<Diagnostic> {
        if table == Table::Overview {
            return [Table::Protocols, Table::Endpoints, Table::Conversations]
                .into_iter()
                .flat_map(|table| {
                    full_sort_selection(report, table, top, sort.or(Some(Sort::Frames)), min_frames)
                })
                .collect();
        }
        let default_sort = if top.is_some()
            && matches!(
                table,
                Table::Conversations | Table::Endpoints | Table::Ports
            ) {
            Some(Sort::Frames)
        } else {
            None
        };
        let mut diagnostics = select(report, table, None, sort.or(default_sort), min_frames);
        let omitted = match table {
            Table::Conversations => cap(
                &mut report.conversations,
                top,
                "stats.conversations_omitted",
                "conversation row(s)",
            ),
            Table::Endpoints => cap(
                &mut report.endpoints,
                top,
                "stats.endpoints_omitted",
                "endpoint row(s)",
            ),
            Table::Protocols => cap(
                &mut report.protocols,
                top,
                "stats.protocols_omitted",
                "protocol row(s)",
            ),
            Table::Ports => cap(&mut report.ports, top, "stats.ports_omitted", "port row(s)"),
            Table::Io => cap(&mut report.io, top, "stats.io_omitted", "io bucket(s)"),
            _ => unreachable!(),
        };
        diagnostics.extend(omitted);
        diagnostics
    }

    #[test]
    fn partial_selection_matches_stable_sort() {
        let mut seed = 42_u64;
        for size in [0, 1, 2, 19, 257] {
            let mut original = report();
            for index in 0..size {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let frames = (seed >> 32) % 5;
                let bytes = (seed >> 37) % 7;
                let key = (seed >> 43) % 4;
                let mut row = conversation(key, key, frames, bytes);
                row.port_a = u16::try_from(index + 1).unwrap();
                original.conversations.push(row);
                original.endpoints.push(EndpointStat {
                    address: format!("192.0.2.{}", key + 1).parse().unwrap(),
                    tx_frames: frames / 2,
                    rx_frames: frames - frames / 2,
                    tx_bytes: bytes / 2,
                    rx_bytes: bytes - bytes / 2,
                });
                original.protocols.push(ProtocolStat {
                    protocol: key.to_string(),
                    frames,
                    bytes,
                });
                original.ports.push(PortStat {
                    transport: StreamTransport::Tcp,
                    port: u16::try_from(key).unwrap(),
                    frames,
                    bytes,
                });
                original.io.push(IoBucketStat {
                    offset: Duration::from_secs(key),
                    frames,
                    bytes,
                });
            }
            for table in [
                Table::Conversations,
                Table::Endpoints,
                Table::Protocols,
                Table::Ports,
                Table::Io,
                Table::Overview,
            ] {
                for sort in [
                    None,
                    Some(Sort::Frames),
                    Some(Sort::Bytes),
                    Some(Sort::Duration),
                ] {
                    if sort == Some(Sort::Duration) && table != Table::Conversations {
                        continue;
                    }
                    for top in [
                        None,
                        Some(0),
                        Some(1),
                        Some(size / 2),
                        Some(size),
                        Some(size + 1),
                    ] {
                        for min_frames in [None, Some(2)] {
                            let mut actual = original.clone();
                            let mut expected = original.clone();
                            let actual_diagnostics =
                                select(&mut actual, table, top, sort, min_frames);
                            let expected_diagnostics =
                                full_sort_selection(&mut expected, table, top, sort, min_frames);
                            assert_eq!(
                                actual, expected,
                                "table={table:?} sort={sort:?} top={top:?} min={min_frames:?}"
                            );
                            assert_eq!(
                                actual_diagnostics, expected_diagnostics,
                                "table={table:?} sort={sort:?} top={top:?} min={min_frames:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn small_top_reduces_comparisons() {
        use std::cell::Cell;
        let mut seed = 23_u64;
        let original = (0..10_000)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                seed >> 16
            })
            .collect::<Vec<_>>();
        let mut partial = original.clone();
        let mut full = original;
        let partial_comparisons = Cell::new(0);
        sort_rows(&mut partial, Some(5), |a, b| {
            partial_comparisons.set(partial_comparisons.get() + 1);
            a.cmp(b)
        });
        let full_comparisons = Cell::new(0);
        full.sort_by(|a, b| {
            full_comparisons.set(full_comparisons.get() + 1);
            a.cmp(b)
        });
        assert_eq!(&partial[..5], &full[..5]);
        assert!(partial_comparisons.get() * 2 < full_comparisons.get());
    }
}
