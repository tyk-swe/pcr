// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use crate::diagnostic::Severity;
use crate::protocol::transport::Tcp;

use super::DirectionState;
use crate::analysis::expert::finding::new as new_finding;
use crate::analysis::expert::observation::TcpObservation;
use crate::analysis::expert::{Finding, FlowKey, TcpEvent, tcp_stream_ref};

pub(super) fn reconcile_events(
    flows: &mut HashMap<FlowKey, DirectionState>,
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
    let before_base = if base_delta < 0x8000_0000 {
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
    flows: &mut HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    reverse: &FlowKey,
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

    if !keep_alive
        && sent.closed
        && payload_len > 0
        && !syn
        && let (Some(base), Some(payload_next)) = (sent.reassembly_base, sent.payload_next)
        && tcp.sequence.wrapping_sub(base) < 0x8000_0000
        && !reassembly_retransmission
    {
        let end = tcp
            .sequence
            .wrapping_add(u32::try_from(payload_len).unwrap_or(u32::MAX));
        if payload_next.wrapping_sub(end) < 0x8000_0000 {
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
        && tcp.sequence != next
        && tcp.sequence.wrapping_sub(next) < 0x8000_0000
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
    }
    update_next_sequences(sent, tcp, payload_len, syn, fin, keep_alive);

    keep_alive
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
        Some(next) if end.wrapping_sub(next) >= 0x8000_0000 => next,
        _ => end,
    });
    if payload_len > 0 {
        let payload_end = tcp
            .sequence
            .wrapping_add(u32::from(syn))
            .wrapping_add(u32::try_from(payload_len).unwrap_or(u32::MAX));
        sent.payload_next = Some(match sent.payload_next {
            Some(next) if payload_end.wrapping_sub(next) >= 0x8000_0000 => next,
            _ => payload_end,
        });
    }
}

pub(super) fn record_clean_closures(
    flows: &mut HashMap<FlowKey, DirectionState>,
    events: &[TcpEvent],
) {
    // A clean close proves delivery only after this frame's header analysis.
    for event in events {
        if let TcpEvent::Closed { flow, reset: false } = event {
            flows.entry(flow.clone()).or_default().closed = true;
        }
    }
}

pub(super) fn finish(
    streams: &HashMap<FlowKey, u64>,
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
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::retransmission_overlap;

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
