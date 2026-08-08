// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TCP sequence progression, gap, keep-alive, and closed-flow retransmission transitions.

use std::collections::HashMap;

use packetcraftr_packet::diagnostic::Severity as DiagnosticSeverity;

use super::super::finding::new as new_finding;
use super::super::observation::TcpObservation;
use super::super::{Finding, FlowKey, TcpEvent};
use super::DirectionState;

pub(super) fn observe(
    flows: &mut HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    reverse: &FlowKey,
    events: &[TcpEvent],
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
        rst,
        ack,
    } = *observation;

    // Keep-alive: one byte or less, sequenced exactly one before what this
    // direction already sent, with no state-changing flag. Against a peer's
    // closed window the same one-byte shape is the persist probe, which the
    // window analysis classifies.
    let peer_zero_window = flows
        .get(reverse)
        .is_some_and(|peer| peer.window == Some(0));
    let sent = flows.entry(flow.clone()).or_default();
    let keep_alive = payload_len <= 1
        && ack
        && !syn
        && !fin
        && !rst
        && !sent.closed
        && !peer_zero_window
        && sent
            .next_sequence
            .is_some_and(|next| tcp.sequence.wrapping_add(1) == next);
    if keep_alive {
        findings.push(new_finding(
            DiagnosticSeverity::Info,
            "tcp.keep_alive",
            number,
            stream,
            format!("{}:{} probes the peer", flow.source, flow.source_port),
        ));
    }

    // After a clean close the reassembler has forgotten the flow, so a late
    // retransmission produces no event there; the close proved contiguous
    // delivery, so a data segment wholly inside the closed payload range
    // repeats observed bytes. The reassembler's byte-exact events stay
    // authoritative whenever it produced any for this flow.
    if !keep_alive
        && sent.closed
        && payload_len > 0
        && !syn
        && let (Some(base), Some(payload_next)) = (sent.reassembly_base, sent.payload_next)
        && tcp.sequence.wrapping_sub(base) < 0x8000_0000
        && !events.iter().any(|event| {
            matches!(
                event,
                TcpEvent::Retransmission { flow: event_flow, .. } if event_flow == flow
            )
        })
    {
        let end = tcp
            .sequence
            .wrapping_add(u32::try_from(payload_len).unwrap_or(u32::MAX));
        if payload_next.wrapping_sub(end) < 0x8000_0000 {
            findings.push(new_finding(
                DiagnosticSeverity::Warning,
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

    // A sequence-consuming segment — data or a FIN — starting past this
    // direction's expected next sequence means the bytes in between never
    // arrived: lost, still in flight, or reordered.
    if !keep_alive
        && (payload_len > 0 || fin)
        && !syn
        && let Some(next) = sent.next_sequence
        && tcp.sequence != next
        && tcp.sequence.wrapping_sub(next) < 0x8000_0000
    {
        findings.push(new_finding(
            DiagnosticSeverity::Warning,
            "tcp.previous_segment_not_captured",
            number,
            stream,
            format!(
                "{}:{} resumes at sequence {} before sequence {next} arrived",
                flow.source, flow.source_port, tcp.sequence
            ),
        ));
    }
    if !keep_alive && (payload_len > 0 || syn || fin) {
        let advance =
            u32::try_from(payload_len).unwrap_or(u32::MAX) + u32::from(syn) + u32::from(fin);
        let end = tcp.sequence.wrapping_add(advance);
        sent.next_sequence = Some(match sent.next_sequence {
            // Sequence numbers wrap, so "later" is serial arithmetic.
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

    keep_alive
}
