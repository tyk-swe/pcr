// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP receive-window advertisement and sender-boundary transitions.

use std::collections::HashMap;

use packetcraftr_packet::diagnostic::DiagnosticSeverity;

use super::super::finding::new as new_finding;
use super::super::observation::TcpObservation;
use super::super::{Finding, FlowKey};
use super::DirectionState;

pub(super) fn report_zero(observation: &TcpObservation<'_>, findings: &mut Vec<Finding>) {
    if observation.tcp.window == 0 && !observation.rst {
        findings.push(new_finding(
            DiagnosticSeverity::Warning,
            "tcp.zero_window",
            observation.number,
            observation.stream,
            format!(
                "{}:{} advertises a zero receive window",
                observation.flow.source, observation.flow.source_port
            ),
        ));
    }
}

pub(super) fn update_advertisement(
    flows: &mut HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
) {
    let TcpObservation { flow, tcp, syn, .. } = *observation;
    let sent = flows.entry(flow.clone()).or_default();
    // Window updates follow TCP's SND.WL1/WL2 rule: a newer segment
    // sequence, or the same sequence with an acknowledgment no older than
    // the last update's. An older retransmission never replaces the window.
    let window_update = match (sent.window_sequence, sent.window_acknowledgment) {
        (Some(update_sequence), Some(update_acknowledgment)) => {
            let sequence_delta = tcp.sequence.wrapping_sub(update_sequence);
            (sequence_delta > 0 && sequence_delta < 0x8000_0000)
                || (tcp.sequence == update_sequence
                    && tcp.acknowledgment.wrapping_sub(update_acknowledgment) < 0x8000_0000)
        }
        _ => true,
    };
    if window_update {
        sent.window = Some(tcp.window);
        sent.window_sequence = Some(tcp.sequence);
        sent.window_acknowledgment = Some(tcp.acknowledgment);
        sent.window_from_syn = syn;
    }
}

pub(super) fn analyze_sender(
    flows: &HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    reverse: &FlowKey,
    keep_alive: bool,
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
    if (payload_len == 0 && !fin) || keep_alive || rst {
        return;
    }
    let Some(peer) = flows.get(reverse).copied() else {
        return;
    };
    let (Some(peer_ack), Some(peer_window)) = (peer.acknowledgment, peer.window) else {
        return;
    };

    // SYN and FIN consume sequence numbers, so a closing data segment can
    // fill the last byte of the window.
    let end = tcp.sequence.wrapping_add(
        u32::try_from(payload_len).unwrap_or(u32::MAX) + u32::from(syn) + u32::from(fin),
    );
    let in_flight = end.wrapping_sub(peer_ack);
    let handshake_seen = peer.syn_seen && flows.get(flow).is_some_and(|sender| sender.syn_seen);
    // Scaling applies only when both SYNs offered it. The receiver's shift is
    // capped at 14, and the SYN's own window is never scaled.
    let shift = match (
        flows.get(flow).and_then(|sender| sender.window_shift),
        peer.window_shift,
    ) {
        (Some(_), Some(peer_shift)) if !peer.window_from_syn => u32::from(peer_shift.min(14)),
        _ => 0,
    };
    let advertised = u64::from(peer_window) << shift;
    if in_flight >= 0x8000_0000 {
        return;
    }

    // A byte at the edge of a zero window is the conventional persist probe;
    // larger sends overrun it. Positive windows distinguish exact fill from
    // an overrun only when the handshake made scaling knowable.
    if peer_window == 0 {
        if in_flight > 0 {
            if payload_len == 1 && !fin && in_flight == 1 {
                findings.push(new_finding(
                    DiagnosticSeverity::Info,
                    "tcp.zero_window_probe",
                    number,
                    stream,
                    format!(
                        "{}:{} probes the peer's zero receive window",
                        flow.source, flow.source_port
                    ),
                ));
            } else {
                findings.push(new_finding(
                    DiagnosticSeverity::Warning,
                    "tcp.window_exceeded",
                    number,
                    stream,
                    format!(
                        "{}:{} has sent {} byte(s) beyond the peer's zero receive window",
                        flow.source,
                        flow.source_port,
                        u64::from(in_flight)
                    ),
                ));
            }
        }
    } else if handshake_seen && u64::from(in_flight) == advertised {
        findings.push(new_finding(
            DiagnosticSeverity::Warning,
            "tcp.window_full",
            number,
            stream,
            format!(
                "{}:{} has filled the peer's {advertised}-byte receive window",
                flow.source, flow.source_port
            ),
        ));
    } else if handshake_seen && u64::from(in_flight) > advertised {
        findings.push(new_finding(
            DiagnosticSeverity::Warning,
            "tcp.window_exceeded",
            number,
            stream,
            format!(
                "{}:{} has sent {} byte(s) beyond the peer's {advertised}-byte receive window",
                flow.source,
                flow.source_port,
                u64::from(in_flight) - advertised
            ),
        ));
    }
}

/// Extracts the shift a SYN's window-scale option advertises, when present.
///
/// Padding is skipped, while an end marker or malformed length stops the
/// defensive walk.
pub(super) fn scale(options: &[u8]) -> Option<u8> {
    let mut rest = options;
    loop {
        match rest {
            [] | [0, ..] => return None,
            [1, tail @ ..] => rest = tail,
            [3, 3, shift, ..] => return Some(*shift),
            [_, length, tail @ ..] if *length >= 2 => {
                rest = tail.get(usize::from(*length) - 2..)?;
            }
            _ => return None,
        }
    }
}
