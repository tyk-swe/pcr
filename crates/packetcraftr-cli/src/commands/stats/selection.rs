// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;

use packetcraftr_core::{analysis::stats::Report, diagnostic::Diagnostic};

use super::arguments::Sort;
use crate::{output::stats::Table, rendering::omitted_diagnostic};

fn rank<T>(
    rows: &mut [T],
    sort: Sort,
    volume: impl Fn(&T) -> (u64, u64),
    key: impl Fn(&T, &T) -> Ordering,
) {
    let metric = |row: &T| {
        let (frames, bytes) = volume(row);
        match sort {
            Sort::Frames => (frames, bytes),
            Sort::Bytes => (bytes, frames),
        }
    };
    rows.sort_by(|left, right| {
        metric(right)
            .cmp(&metric(left))
            .then_with(|| key(left, right))
    });
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
) -> Vec<Diagnostic> {
    match table {
        Table::Overview => [Table::Protocols, Table::Endpoints, Table::Conversations]
            .into_iter()
            .flat_map(|table| select(report, table, top, Some(sort.unwrap_or(Sort::Frames))))
            .collect(),
        Table::Conversations => {
            if let Some(sort) = sort.or_else(|| top.map(|_| Sort::Frames)) {
                rank(
                    &mut report.conversations,
                    sort,
                    |row| {
                        (
                            row.frames_a_to_b.saturating_add(row.frames_b_to_a),
                            row.bytes_a_to_b.saturating_add(row.bytes_b_to_a),
                        )
                    },
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
                    sort,
                    |row| (row.frames, row.bytes),
                    |a, b| a.offset.cmp(&b.offset),
                );
            }
            cap(&mut report.io, top, "stats.io_omitted", "io bucket(s)")
        }
        Table::Fragments => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::analysis::stats::{Collector, EndpointStat};
    use std::time::Duration;

    #[test]
    fn equal_metrics_use_keys_regardless_of_input_order() {
        for sort in [Sort::Frames, Sort::Bytes] {
            let mut rows = [("z", 2, 10), ("c", 2, 10), ("a", 2, 20), ("b", 3, 10)];
            rank(&mut rows, sort, |r| (r.1, r.2), |a, b| a.0.cmp(b.0));
            assert_eq!(
                rows.map(|r| r.0),
                match sort {
                    Sort::Frames => ["b", "a", "c", "z"],
                    Sort::Bytes => ["a", "b", "c", "z"],
                }
            );
        }
    }

    #[test]
    fn endpoint_ranking_combines_both_directions_before_retention() {
        for sort in [Sort::Frames, Sort::Bytes] {
            let mut report = Collector::new(Duration::from_secs(1))
                .unwrap()
                .finish(&Default::default());
            report.endpoints = vec![
                EndpointStat {
                    address: "192.0.2.1".parse().unwrap(),
                    tx_frames: 3,
                    tx_bytes: 30,
                    rx_frames: 0,
                    rx_bytes: 0,
                },
                EndpointStat {
                    address: "192.0.2.2".parse().unwrap(),
                    tx_frames: 2,
                    tx_bytes: 20,
                    rx_frames: 2,
                    rx_bytes: 20,
                },
            ];
            let diagnostics = select(&mut report, Table::Endpoints, Some(1), Some(sort));
            assert_eq!(report.endpoints[0].address.to_string(), "192.0.2.2");
            assert_eq!(diagnostics.len(), 1);
        }
    }
}
