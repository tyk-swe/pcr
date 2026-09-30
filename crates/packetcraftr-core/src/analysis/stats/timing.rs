// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    analysis::{conversation_index::CanonicalFlow, reassembly::tcp::ScopedFlowKey},
    protocol::transport::Tcp,
};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, SystemTime},
};

const MAX_PENDING: usize = 4096;
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct AckRttStat {
    pub count: u64,
    pub minimum: Option<Duration>,
    pub mean: Option<Duration>,
    pub maximum: Option<Duration>,
    pub excluded_retransmission: u64,
    pub excluded_clock_regression: u64,
    pub excluded_missing_ack: u64,
    pub excluded_limit: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TcpTimingStat {
    pub stream: u64,
    pub handshake_syn_to_syn_ack: Option<Duration>,
    pub handshake_syn_to_ack: Option<Duration>,
    pub ack_rtt_a_to_b: AckRttStat,
    pub ack_rtt_b_to_a: AckRttStat,
}
#[derive(Debug)]
struct Sent {
    start: u32,
    end: u32,
    time: SystemTime,
    ambiguous: bool,
}
#[derive(Debug, Default)]
struct Direction {
    pending: VecDeque<Sent>,
    observed: VecDeque<(u32, u32)>,
    range_edges: BTreeMap<u32, usize>,
    wrapping_ranges: usize,
    forgotten_through: Option<u32>,
    sum: u128,
    report: AckRttStat,
}
fn at_or_after(value: u32, reference: u32) -> bool {
    value.wrapping_sub(reference) < 0x8000_0000
}
fn overlaps(start: u32, end: u32, other_start: u32, other_end: u32) -> bool {
    at_or_after(end, other_start.wrapping_add(1)) && at_or_after(other_end, start.wrapping_add(1))
}
impl Direction {
    fn retain_range(&mut self, start: u32, end: u32) {
        for edge in [start, end] {
            *self.range_edges.entry(edge).or_default() += 1;
        }
        self.wrapping_ranges += usize::from(end < start);
    }
    fn release_range(&mut self, start: u32, end: u32) {
        for edge in [start, end] {
            let count = self
                .range_edges
                .get_mut(&edge)
                .expect("retained range edge");
            *count -= 1;
            if *count == 0 {
                self.range_edges.remove(&edge);
            }
        }
        self.wrapping_ranges -= usize::from(end < start);
    }
    fn disjoint_from_bounds(&self, start: u32, end: u32) -> bool {
        let Some((&low, _)) = self.range_edges.first_key_value() else {
            return true;
        };
        let (&high, _) = self.range_edges.last_key_value().expect("nonempty edges");
        // A disjoint numeric envelope entirely within a serial-number
        // half-space proves nonoverlap, even after earlier reordering. Ranges
        // crossing zero or spanning half the sequence space use the full scan.
        self.wrapping_ranges == 0
            && start <= end
            && (start >= high && end.wrapping_sub(low) < 0x8000_0000
                || end <= low && high.wrapping_sub(start) < 0x8000_0000)
    }
    fn sent(&mut self, start: u32, length: u32, time: SystemTime, regressed: bool) {
        if length == 0 {
            return;
        }
        let end = start.wrapping_add(length);
        let ambiguous = !self.disjoint_from_bounds(start, end)
            && (self
                .observed
                .iter()
                .any(|&(old_start, old_end)| overlaps(start, end, old_start, old_end))
                || self
                    .pending
                    .iter()
                    .any(|old| overlaps(start, end, old.start, old.end)));
        if ambiguous {
            for old in &mut self.pending {
                if overlaps(start, end, old.start, old.end) {
                    old.ambiguous = true;
                }
            }
        }
        if self.observed.len() == MAX_PENDING
            && let Some((old_start, old_end)) = self.observed.pop_front()
        {
            self.release_range(old_start, old_end);
            if self
                .forgotten_through
                .is_none_or(|edge| at_or_after(old_end, edge))
            {
                self.forgotten_through = Some(old_end);
            }
        }
        self.observed.push_back((start, end));
        self.retain_range(start, end);
        if regressed {
            self.report.excluded_clock_regression += 1;
            return;
        }
        // Once history is discarded, an older arrival cannot be classified
        // safely as either reordering or retransmission. Exclude it as a
        // resource limit instead of manufacturing an unambiguous sample.
        if !ambiguous
            && self
                .forgotten_through
                .is_some_and(|edge| !at_or_after(start, edge))
        {
            self.report.excluded_limit += 1;
            return;
        }
        if self.pending.len() == MAX_PENDING {
            if let Some(old) = self.pending.pop_front() {
                self.release_range(old.start, old.end);
            }
            self.report.excluded_limit += 1;
        }
        self.pending.push_back(Sent {
            start,
            end,
            time,
            ambiguous,
        });
        self.retain_range(start, end);
    }
    fn acknowledged(&mut self, ack: u32, time: SystemTime, regressed: bool) {
        let mut remaining = VecDeque::new();
        while let Some(sent) = self.pending.pop_front() {
            if !at_or_after(ack, sent.end) {
                remaining.push_back(sent);
                continue;
            }
            self.release_range(sent.start, sent.end);
            if sent.ambiguous {
                self.report.excluded_retransmission += 1;
                continue;
            }
            let Ok(duration) = time.duration_since(sent.time) else {
                self.report.excluded_clock_regression += 1;
                continue;
            };
            if regressed {
                self.report.excluded_clock_regression += 1;
                continue;
            }
            let Some(sum) = self.sum.checked_add(duration.as_nanos()) else {
                self.report.excluded_limit += 1;
                continue;
            };
            self.report.count += 1;
            self.sum = sum;
            self.report.minimum = Some(self.report.minimum.map_or(duration, |d| d.min(duration)));
            self.report.maximum = Some(self.report.maximum.map_or(duration, |d| d.max(duration)));
        }
        self.pending = remaining;
    }
    fn finish(mut self) -> AckRttStat {
        self.report.excluded_missing_ack += self.pending.len() as u64;
        if self.report.count > 0 {
            self.report.mean = Some(super::duration_from_nanos_saturating(
                self.sum / u128::from(self.report.count),
            ));
        }
        self.report
    }
    fn reset_connection(&mut self) {
        self.report.excluded_missing_ack += self.pending.len() as u64;
        self.pending.clear();
        self.observed.clear();
        self.range_edges.clear();
        self.wrapping_ranges = 0;
        self.forgotten_through = None;
    }
}
#[derive(Debug)]
pub(super) struct State {
    stream: u64,
    canonical: CanonicalFlow,
    directions: [Direction; 2],
    syn: Option<(usize, u32, SystemTime)>,
    syn_ack: Option<(u32, SystemTime)>,
    syn_to_syn_ack: Option<Duration>,
    syn_to_ack: Option<Duration>,
    final_ack_seen: bool,
    handshake_ambiguous: bool,
    observed: bool,
    closed: bool,
}
impl State {
    pub(super) fn new(stream: u64, flow: &ScopedFlowKey) -> Self {
        Self {
            stream,
            canonical: CanonicalFlow::from_flow(flow),
            directions: [Direction::default(), Direction::default()],
            syn: None,
            syn_ack: None,
            syn_to_syn_ack: None,
            syn_to_ack: None,
            final_ack_seen: false,
            handshake_ambiguous: false,
            observed: false,
            closed: false,
        }
    }
    pub(super) fn observe(
        &mut self,
        flow: &ScopedFlowKey,
        tcp: &Tcp,
        payload: usize,
        time: SystemTime,
        regressed: bool,
    ) {
        let direction =
            usize::from((flow.flow.source, flow.flow.source_port) != self.canonical.first);
        if tcp.flags & Tcp::SYN != 0 && tcp.flags & Tcp::ACK == 0 {
            let reused = self.closed
                || self.syn.is_some_and(|(sender, sequence, _)| {
                    sender == direction && sequence != tcp.sequence
                        || sender != direction && self.final_ack_seen
                })
                || self.syn.is_none() && self.observed;
            if reused {
                for direction in &mut self.directions {
                    direction.reset_connection();
                }
                self.syn = None;
                self.syn_ack = None;
                self.syn_to_syn_ack = None;
                self.syn_to_ack = None;
                self.final_ack_seen = false;
                self.handshake_ambiguous = false;
                self.closed = false;
            }
            self.handshake_ambiguous |= regressed;
            if self.syn.is_some() {
                self.handshake_ambiguous = true;
            } else {
                self.syn = Some((direction, tcp.sequence, time));
            }
        } else if tcp.flags & (Tcp::SYN | Tcp::ACK) == Tcp::SYN | Tcp::ACK
            && let Some((sender, sequence, start)) = self.syn
            && direction != sender
            && tcp.acknowledgment == sequence.wrapping_add(1)
        {
            if self.syn_ack.is_some() {
                self.handshake_ambiguous = true;
            } else {
                self.syn_ack = Some((tcp.sequence, time));
                if !regressed {
                    self.syn_to_syn_ack = time.duration_since(start).ok();
                }
            }
        } else if tcp.flags & Tcp::ACK != 0
            && let Some((sender, client_sequence, start)) = self.syn
            && direction == sender
            && tcp.sequence == client_sequence.wrapping_add(1)
            && let Some((sequence, _)) = self.syn_ack
            && tcp.acknowledgment == sequence.wrapping_add(1)
            && !self.final_ack_seen
        {
            self.final_ack_seen = true;
            if !regressed {
                self.syn_to_ack = time.duration_since(start).ok();
            }
        }
        if tcp.flags & Tcp::ACK != 0 {
            self.directions[1 - direction].acknowledged(tcp.acknowledgment, time, regressed);
        }
        let length = (payload as u32)
            .saturating_add(u32::from(tcp.flags & Tcp::SYN != 0))
            .saturating_add(u32::from(tcp.flags & Tcp::FIN != 0));
        self.directions[direction].sent(tcp.sequence, length, time, regressed);
        self.observed = true;
        self.closed |= tcp.flags & (Tcp::FIN | Tcp::RST) != 0;
    }
    pub(super) fn finish(self) -> TcpTimingStat {
        let [a, b] = self.directions;
        TcpTimingStat {
            stream: self.stream,
            handshake_syn_to_syn_ack: (!self.handshake_ambiguous)
                .then_some(self.syn_to_syn_ack)
                .flatten(),
            handshake_syn_to_ack: (!self.handshake_ambiguous)
                .then_some(self.syn_to_ack)
                .flatten(),
            ack_rtt_a_to_b: a.finish(),
            ack_rtt_b_to_a: b.finish(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;
    #[test]
    fn million_sequential_segments_keep_timing_bounded_across_wrap() {
        let started = std::time::Instant::now();
        let mut direction = Direction::default();
        let mut sequence = u32::MAX - 7000;
        // Start with reordered disjoint ranges so the optimization must recover
        // after reordering rather than work only on a pristine ordered stream.
        direction.sent(sequence.wrapping_sub(1400), 1400, UNIX_EPOCH, false);
        direction.sent(sequence.wrapping_sub(2800), 1400, UNIX_EPOCH, false);
        direction.acknowledged(sequence, UNIX_EPOCH + Duration::from_millis(1), false);
        for _ in 0..1_000_000 {
            direction.sent(sequence, 1400, UNIX_EPOCH, false);
            sequence = sequence.wrapping_add(1400);
            direction.acknowledged(sequence, UNIX_EPOCH + Duration::from_millis(1), false);
        }
        let report = direction.finish();
        assert_eq!(report.count, 1_000_002);
        assert_eq!(report.excluded_retransmission, 0);
        assert_eq!(report.excluded_limit, 0);
        assert_eq!(report.mean, Some(Duration::from_millis(1)));
        // The limit tolerates slow CI hosts but catches billions of history scans.
        assert!(started.elapsed() < Duration::from_secs(30));
    }
    #[test]
    fn forgotten_history_is_excluded_instead_of_assumed_unambiguous() {
        let mut direction = Direction::default();
        for sequence in 0..=MAX_PENDING as u32 {
            direction.sent(sequence, 1, UNIX_EPOCH, false);
            direction.acknowledged(sequence + 1, UNIX_EPOCH + Duration::from_secs(1), false);
        }
        direction.sent(0, 1, UNIX_EPOCH, false);
        direction.acknowledged(
            MAX_PENDING as u32 + 1,
            UNIX_EPOCH + Duration::from_secs(1),
            false,
        );
        assert_eq!(direction.report.count, MAX_PENDING as u64 + 1);
        assert_eq!(direction.report.excluded_limit, 1);
    }
    #[test]
    fn reordered_ranges_across_wrap_and_partial_retransmissions_are_distinct() {
        let mut direction = Direction::default();
        direction.sent(0, 3, UNIX_EPOCH, false);
        direction.sent(u32::MAX - 2, 3, UNIX_EPOCH, false);
        direction.acknowledged(3, UNIX_EPOCH + Duration::from_secs(1), false);
        assert_eq!(direction.report.count, 2);
        assert_eq!(direction.report.excluded_retransmission, 0);
        direction.sent(3, 4, UNIX_EPOCH, false);
        direction.sent(5, 4, UNIX_EPOCH, false);
        direction.acknowledged(9, UNIX_EPOCH + Duration::from_secs(1), false);
        assert_eq!(direction.report.count, 2);
        assert_eq!(direction.report.excluded_retransmission, 2);
        // A duplicate of already acknowledged data remains ambiguous.
        direction.sent(3, 4, UNIX_EPOCH, false);
        direction.acknowledged(9, UNIX_EPOCH + Duration::from_secs(1), false);
        assert_eq!(direction.report.excluded_retransmission, 3);
    }
    #[test]
    fn wrap_and_retransmissions_obey_karn_and_regressions_are_excluded() {
        let mut direction = Direction::default();
        direction.sent(u32::MAX - 3, 8, UNIX_EPOCH, false);
        direction.acknowledged(4, UNIX_EPOCH + Duration::from_millis(10), false);
        assert_eq!(direction.report.count, 1);
        direction.sent(4, 10, UNIX_EPOCH, false);
        direction.sent(4, 10, UNIX_EPOCH, false);
        direction.acknowledged(14, UNIX_EPOCH + Duration::from_millis(20), false);
        assert_eq!(direction.report.count, 1);
        assert_eq!(direction.report.excluded_retransmission, 2);
        direction.sent(14, 10, UNIX_EPOCH + Duration::from_secs(3), false);
        direction.acknowledged(24, UNIX_EPOCH, false);
        assert_eq!(direction.report.excluded_clock_regression, 1);
    }
    #[test]
    fn handshake_requires_sequence_matching_and_keeps_regressed_final_ack_excluded() {
        use crate::analysis::{reassembly::tcp::FlowKey, scope::Interner};
        let flow = ScopedFlowKey {
            scope: Interner::new().intern(None, Vec::new()).unwrap(),
            flow: FlowKey {
                source: "192.0.2.1".parse().unwrap(),
                destination: "198.51.100.2".parse().unwrap(),
                source_port: 40000,
                destination_port: 80,
            },
        };
        for (final_sequence, regressed) in [(0, false), (10, false), (0, true)] {
            let mut state = State::new(0, &flow);
            state.observe(
                &flow,
                &Tcp {
                    sequence: u32::MAX,
                    flags: Tcp::SYN,
                    ..Default::default()
                },
                0,
                UNIX_EPOCH,
                false,
            );
            state.observe(
                &flow.reverse(),
                &Tcp {
                    sequence: 5,
                    acknowledgment: 0,
                    flags: Tcp::SYN | Tcp::ACK,
                    ..Default::default()
                },
                0,
                UNIX_EPOCH + Duration::from_secs(1),
                false,
            );
            let ack = Tcp {
                sequence: final_sequence,
                acknowledgment: 6,
                flags: Tcp::ACK,
                ..Default::default()
            };
            state.observe(
                &flow,
                &ack,
                0,
                UNIX_EPOCH + Duration::from_secs(2),
                regressed,
            );
            if regressed {
                state.observe(&flow, &ack, 0, UNIX_EPOCH + Duration::from_secs(3), false);
            }
            let report = state.finish();
            assert_eq!(
                report.handshake_syn_to_ack,
                if final_sequence == 0 && !regressed {
                    Some(Duration::from_secs(2))
                } else {
                    None
                }
            );
        }
    }
}
