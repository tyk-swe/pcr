// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use crate::diagnostic::Severity;
use crate::protocol::transport::Tcp;

use super::DirectionState;
use crate::analysis::expert::finding::new as new_finding;
use crate::analysis::expert::observation::TcpObservation;
use crate::analysis::expert::{Finding, ScopedFlowKey, TcpEvent, tcp_stream_ref};
use crate::analysis::serial::{serial_ge, serial_gt};

/// Duplicate acknowledgments after which a resend of the acknowledged edge is a fast retransmission.
const FAST_RETRANSMIT_DUPLICATES: u64 = 3;

/// Gaps one direction can hold open at once; gaps opened beyond this go unwatched.
const MAX_OPEN_HOLES: usize = 4;

/// Sequence space `[start, end)` a direction skipped over, kept as one fixed-size record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Hole {
    start: u32,
    end: u32,
}

impl Hole {
    fn contains(self, sequence: u32) -> bool {
        serial_ge(sequence, self.start) && serial_gt(self.end, sequence)
    }

    /// What remains of the hole once `[sequence, segment_end)` arrived inside it.
    fn fill(self, sequence: u32, segment_end: u32) -> Option<Self> {
        let remaining = if sequence == self.start {
            Self {
                start: if serial_ge(segment_end, self.end) {
                    self.end
                } else {
                    segment_end
                },
                end: self.end,
            }
        } else if serial_ge(segment_end, self.end) {
            Self {
                start: self.start,
                end: sequence,
            }
        } else {
            self
        };
        (remaining.start != remaining.end).then_some(remaining)
    }
}

/// The gaps a direction has skipped over and not yet filled, in a fixed number of slots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Holes {
    slots: [Option<Hole>; MAX_OPEN_HOLES],
}

impl Holes {
    /// Watches a gap beyond every open one; a full set keeps its older gaps.
    fn open(&mut self, hole: Hole) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(hole);
        }
    }

    /// Whether `sequence` lies in an open gap, shrinking that gap by `[sequence, segment_end)`.
    fn fill(&mut self, sequence: u32, segment_end: u32) -> bool {
        let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_some_and(|hole| hole.contains(sequence)))
        else {
            return false;
        };
        *slot = slot.and_then(|hole| hole.fill(sequence, segment_end));
        true
    }
}

pub(super) fn reconcile_events(
    flows: &mut HashMap<ScopedFlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    events: &[TcpEvent],
    findings: &mut Vec<Finding>,
) -> (bool, bool) {
    let probe_shape = is_probe_shape(flows.get(observation.flow), observation);
    let mut reassembly_retransmission = false;
    for event in events {
        let TcpEvent::Retransmission {
            flow,
            sequence,
            bytes,
            conflicting,
            ..
        } = event
        else {
            continue;
        };
        if flow == observation.flow {
            reassembly_retransmission = true;
        }
        if probe_shape || observation.rst {
            continue;
        }
        let Some(base) = flows.get(flow).and_then(|state| state.reassembly_base) else {
            continue;
        };
        let (observed, whole_segment) =
            retransmission_overlap(base, *sequence, observation.payload_len, *bytes);
        if observed == 0 {
            continue;
        }
        let fast = if *conflicting {
            None
        } else {
            fast_retransmit_duplicates(flows.get(&flow.reverse()), *sequence)
        };
        if let Some(duplicates) = fast {
            if let Some(peer) = flows.get_mut(&flow.reverse()) {
                peer.fast_retransmit_reported = true;
            }
            findings.push(new_finding(
                Severity::Warning,
                "tcp.fast_retransmission",
                observation.number,
                observation.stream,
                format!(
                    "{observed} byte(s) at sequence {sequence} are resent after {duplicates} \
                     duplicate acknowledgments of that sequence"
                ),
            ));
            continue;
        }
        findings.push(new_finding(
            if *conflicting {
                Severity::Error
            } else {
                Severity::Warning
            },
            if *conflicting {
                "tcp.retransmission_conflicting"
            } else {
                "tcp.retransmission"
            },
            observation.number,
            observation.stream,
            retransmission_message(observed, *sequence, whole_segment, *conflicting),
        ));
    }
    (probe_shape, reassembly_retransmission)
}

/// Duplicate acknowledgments of `sequence` that justify calling its resend a fast retransmission.
fn fast_retransmit_duplicates(peer: Option<&DirectionState>, sequence: u32) -> Option<u64> {
    let peer = peer?;
    (peer.acknowledgment == Some(sequence)
        && peer.duplicate_acks >= FAST_RETRANSMIT_DUPLICATES
        && !peer.fast_retransmit_reported)
        .then_some(peer.duplicate_acks)
}

fn is_probe_shape(state: Option<&DirectionState>, observation: &TcpObservation<'_>) -> bool {
    observation.payload_len <= 1
        && observation.ack
        && !observation.syn
        && !observation.fin
        && !observation.rst
        && state.is_some_and(|state| {
            !state.closed
                && state
                    .next_sequence
                    .is_some_and(|next| observation.tcp.sequence.wrapping_add(1) == next)
        })
}

fn retransmission_overlap(
    capture_base: u32,
    sequence: u32,
    payload_len: usize,
    retransmitted: usize,
) -> (u64, bool) {
    // Bytes before the capture base were never observed, including across wraparound.
    let length = u32::try_from(payload_len).unwrap_or(u32::MAX);
    let base_delta = capture_base.wrapping_sub(sequence);
    let before_base = if serial_ge(capture_base, sequence) {
        base_delta.min(length)
    } else {
        0
    };
    let observed = u64::try_from(retransmitted)
        .unwrap_or(u64::MAX)
        .saturating_sub(u64::from(before_base));
    (observed, before_base == 0 && retransmitted == payload_len)
}

fn retransmission_message(
    bytes: u64,
    sequence: u32,
    whole_segment: bool,
    conflicting: bool,
) -> String {
    let placement = if whole_segment {
        "at sequence"
    } else {
        "within the segment at sequence"
    };
    let conflict = if conflicting {
        " with different content"
    } else {
        ""
    };
    format!("{bytes} byte(s) {placement} {sequence} retransmit previously seen data{conflict}")
}

pub(super) fn observe(
    flows: &mut HashMap<ScopedFlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    reverse: &ScopedFlowKey,
    probe_shape: bool,
    reassembly_retransmission: bool,
    findings: &mut Vec<Finding>,
) -> bool {
    let TcpObservation {
        number,
        stream,
        flow,
        tcp,
        payload_len,
        syn,
        fin,
        ..
    } = *observation;

    let peer_zero_window = flows
        .get(reverse)
        .is_some_and(|peer| peer.window == Some(0));
    let sent = flows.entry(flow.clone()).or_default();
    let keep_alive = probe_shape && !peer_zero_window;
    if keep_alive {
        findings.push(new_finding(
            Severity::Info,
            "tcp.keep_alive",
            number,
            stream,
            format!(
                "{}:{} probes the peer",
                flow.flow.source, flow.flow.source_port
            ),
        ));
    }

    let segment_length = u32::try_from(payload_len).unwrap_or(u32::MAX);
    let hole_fill = if !keep_alive
        && payload_len > 0
        && !syn
        && !reassembly_retransmission
        && sent
            .holes
            .fill(tcp.sequence, tcp.sequence.wrapping_add(segment_length))
    {
        findings.push(new_finding(
            Severity::Warning,
            "tcp.out_of_order",
            number,
            stream,
            format!(
                "{}:{} delivers the missing segment at sequence {} after later data",
                flow.flow.source, flow.flow.source_port, tcp.sequence
            ),
        ));
        true
    } else {
        false
    };

    if !keep_alive
        && !hole_fill
        && sent.closed
        && payload_len > 0
        && !syn
        && let (Some(base), Some(payload_next)) = (sent.reassembly_base, sent.payload_next)
        && serial_ge(tcp.sequence, base)
        && !reassembly_retransmission
    {
        let end = tcp.sequence.wrapping_add(segment_length);
        if serial_ge(payload_next, end) {
            findings.push(new_finding(
                Severity::Warning,
                "tcp.retransmission",
                number,
                stream,
                format!(
                    "{payload_len} byte(s) at sequence {} retransmit previously seen data",
                    tcp.sequence
                ),
            ));
        }
    }

    if !keep_alive
        && (payload_len > 0 || fin)
        && !syn
        && let Some(next) = sent.next_sequence
        && serial_gt(tcp.sequence, next)
    {
        findings.push(new_finding(
            Severity::Warning,
            "tcp.previous_segment_not_captured",
            number,
            stream,
            format!(
                "{}:{} resumes at sequence {} before sequence {next} arrived",
                flow.flow.source, flow.flow.source_port, tcp.sequence
            ),
        ));
        sent.holes.open(Hole {
            start: next,
            end: tcp.sequence,
        });
    }
    observe_close(
        sent,
        observation,
        keep_alive,
        reassembly_retransmission,
        findings,
    );
    update_next_sequences(sent, tcp, payload_len, syn, fin, keep_alive);

    keep_alive
}

/// Tracks the sender's first FIN and flags what it sends against that FIN afterwards.
fn observe_close(
    sent: &mut DirectionState,
    observation: &TcpObservation<'_>,
    keep_alive: bool,
    reassembly_retransmission: bool,
    findings: &mut Vec<Finding>,
) {
    let TcpObservation {
        number,
        stream,
        flow,
        tcp,
        payload_len,
        syn,
        fin,
        rst,
        ..
    } = *observation;
    if keep_alive || rst || syn {
        return;
    }
    let fin_position = tcp
        .sequence
        .wrapping_add(u32::try_from(payload_len).unwrap_or(u32::MAX));
    match sent.fin_sequence {
        Some(first) if payload_len > 0 && serial_ge(tcp.sequence, first) => {
            findings.push(new_finding(
                Severity::Warning,
                "tcp.data_after_close",
                number,
                stream,
                format!(
                    "{}:{} sent {payload_len} byte(s) at sequence {} after its FIN at sequence {first}",
                    flow.flow.source, flow.flow.source_port, tcp.sequence
                ),
            ));
        }
        Some(first) if fin && fin_position == first && !reassembly_retransmission => {
            findings.push(new_finding(
                Severity::Info,
                "tcp.fin_retransmission",
                number,
                stream,
                format!(
                    "{}:{} resends its FIN at sequence {first}",
                    flow.flow.source, flow.flow.source_port
                ),
            ));
        }
        None if fin => sent.fin_sequence = Some(fin_position),
        _ => {}
    }
}

fn update_next_sequences(
    sent: &mut DirectionState,
    tcp: &Tcp,
    payload_len: usize,
    syn: bool,
    fin: bool,
    keep_alive: bool,
) {
    if keep_alive || (payload_len == 0 && !syn && !fin) {
        return;
    }
    let advance = u32::try_from(payload_len)
        .unwrap_or(u32::MAX)
        .saturating_add(u32::from(syn))
        .saturating_add(u32::from(fin));
    let end = tcp.sequence.wrapping_add(advance);
    sent.next_sequence = Some(match sent.next_sequence {
        Some(next) if !serial_ge(end, next) => next,
        _ => end,
    });
    if payload_len > 0 {
        let payload_end = tcp
            .sequence
            .wrapping_add(u32::from(syn))
            .wrapping_add(u32::try_from(payload_len).unwrap_or(u32::MAX));
        sent.payload_next = Some(match sent.payload_next {
            Some(next) if !serial_ge(payload_end, next) => next,
            _ => payload_end,
        });
    }
}

pub(super) fn record_clean_closures(
    flows: &mut HashMap<ScopedFlowKey, DirectionState>,
    events: &[TcpEvent],
) {
    for event in events {
        if let TcpEvent::Closed { flow, reset: false } = event {
            flows.entry(flow.clone()).or_default().closed = true;
        }
    }
}

pub(in crate::analysis::expert) fn finish(
    streams: &HashMap<ScopedFlowKey, u64>,
    events: &[TcpEvent],
    end_number: u64,
) -> Vec<Finding> {
    events
        .iter()
        .filter_map(|event| {
            let TcpEvent::Evicted {
                flow,
                pending_bytes,
            } = event
            else {
                return None;
            };
            if *pending_bytes == 0 {
                return None;
            }
            Some(new_finding(
                Severity::Info,
                "tcp.incomplete_at_end",
                end_number,
                streams
                    .get(flow)
                    .or_else(|| streams.get(&flow.reverse()))
                    .copied()
                    .map(tcp_stream_ref),
                format!(
                    "{} byte(s) from {}:{} were still awaiting missing earlier data \
                     when the capture ended",
                    pending_bytes, flow.flow.source, flow.flow.source_port
                ),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {

    use super::{Hole, Holes, MAX_OPEN_HOLES, retransmission_overlap};

    #[test]
    fn hole_fill_shrinks_from_either_edge_and_across_wraparound() {
        let hole = Hole {
            start: u32::MAX - 1,
            end: 4,
        };
        assert!(hole.contains(u32::MAX));
        assert!(hole.contains(3));
        assert!(!hole.contains(4));
        assert!(!hole.contains(u32::MAX - 2));

        let front = hole.fill(u32::MAX - 1, 1).expect("front fill leaves a gap");
        assert_eq!((front.start, front.end), (1, 4));
        let back = hole.fill(u32::MAX, 9).expect("back fill leaves a gap");
        assert_eq!((back.start, back.end), (u32::MAX - 1, u32::MAX));
        assert_eq!(hole.fill(u32::MAX - 1, 4), None);
        assert_eq!(hole.fill(u32::MAX - 1, 9), None);
        assert_eq!(hole.fill(u32::MAX, 2), Some(hole));
    }

    #[test]
    fn open_holes_fill_independently_and_keep_older_gaps_when_full() {
        let mut holes = Holes::default();
        for index in 0..=MAX_OPEN_HOLES {
            let start = u32::try_from(index).expect("small index") * 10 + 2;
            holes.open(Hole {
                start,
                end: start + 3,
            });
        }

        assert!(holes.fill(12, 15), "a later gap fills without the first");
        assert!(!holes.fill(12, 15), "a filled gap is not filled twice");
        assert!(holes.fill(2, 4), "the oldest gap is still watched");
        assert!(holes.fill(4, 5), "a partly filled gap keeps its remainder");
        assert!(!holes.fill(4, 5));
        let overflow = u32::try_from(MAX_OPEN_HOLES).expect("small count") * 10 + 2;
        assert!(
            !holes.fill(overflow, overflow + 3),
            "the newest gap was dropped"
        );
    }

    #[test]
    fn retransmission_overlap_respects_capture_base_and_wraparound() {
        struct Case {
            name: &'static str,
            capture_base: u32,
            sequence: u32,
            payload_len: usize,
            retransmitted: usize,
            expected: (u64, bool),
        }

        let cases = [
            Case {
                name: "whole segment",
                capture_base: 100,
                sequence: 100,
                payload_len: 3,
                retransmitted: 3,
                expected: (3, true),
            },
            Case {
                name: "partial overlap",
                capture_base: 100,
                sequence: 100,
                payload_len: 5,
                retransmitted: 2,
                expected: (2, false),
            },
            Case {
                name: "partly before capture",
                capture_base: 100,
                sequence: 98,
                payload_len: 5,
                retransmitted: 5,
                expected: (3, false),
            },
            Case {
                name: "entirely before capture",
                capture_base: 100,
                sequence: 95,
                payload_len: 5,
                retransmitted: 5,
                expected: (0, false),
            },
            Case {
                name: "capture base wraps within segment",
                capture_base: 1,
                sequence: u32::MAX - 1,
                payload_len: 5,
                retransmitted: 5,
                expected: (2, false),
            },
            Case {
                name: "segment starts after wrapped base",
                capture_base: u32::MAX - 1,
                sequence: 1,
                payload_len: 5,
                retransmitted: 5,
                expected: (5, true),
            },
        ];

        for case in cases {
            assert_eq!(
                retransmission_overlap(
                    case.capture_base,
                    case.sequence,
                    case.payload_len,
                    case.retransmitted,
                ),
                case.expected,
                "{}",
                case.name
            );
        }
    }
}
