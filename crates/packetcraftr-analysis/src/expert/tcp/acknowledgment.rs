// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Duplicate-ACK detection and monotonic acknowledgment transitions.

use std::collections::HashMap;

use packetcraftr_packet::diagnostic::Severity as DiagnosticSeverity;

use super::super::finding::new as new_finding;
use super::super::observation::TcpObservation;
use super::super::{Finding, FlowKey};
use super::DirectionState;

pub(super) fn observe_duplicate(
    flows: &mut HashMap<FlowKey, DirectionState>,
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
        ack,
    } = *observation;

    // A duplicate acknowledgment is a pure repeat from the same direction.
    // It is loss evidence only while the peer has payload outstanding beyond
    // it. A zero-length keep-alive repeats the prior ACK but is already
    // classified as the probe it is.
    if ack && payload_len == 0 && !keep_alive && !syn && !fin && !rst {
        let outstanding = flows.get(reverse).is_none_or(|peer| {
            peer.payload_next.is_some_and(|next| {
                let delta = next.wrapping_sub(tcp.acknowledgment);
                delta > 0 && delta < 0x8000_0000
            })
        });
        let sent = flows.entry(flow.clone()).or_default();
        if sent.acknowledgment == Some(tcp.acknowledgment) && sent.window == Some(tcp.window) {
            sent.duplicate_acks += 1;
            let count = sent.duplicate_acks;
            if outstanding {
                findings.push(new_finding(
                    DiagnosticSeverity::Warning,
                    "tcp.duplicate_ack",
                    number,
                    stream,
                    format!(
                        "{}:{} repeats acknowledgment {} (duplicate #{count})",
                        flow.source, flow.source_port, tcp.acknowledgment
                    ),
                ));
            }
        } else {
            sent.duplicate_acks = 0;
        }
    }
}

/// Records a non-backward acknowledgment and reports whether the same header
/// is eligible to update its advertised window.
pub(super) fn update(
    flows: &mut HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    syn_renews: bool,
) -> bool {
    let TcpObservation {
        flow,
        tcp,
        syn,
        ack,
        ..
    } = *observation;
    if !ack && !syn {
        return false;
    }

    let sent = flows.entry(flow.clone()).or_default();
    // A reordered or retransmitted segment can carry an older
    // acknowledgment; TCP never moves the acknowledged point backward.
    let backward = ack
        && sent
            .acknowledgment
            .is_some_and(|previous| tcp.acknowledgment.wrapping_sub(previous) >= 0x8000_0000);
    if backward || (syn_renews && sent.acknowledgment.is_some()) {
        return false;
    }

    if ack {
        // A changed acknowledgment or window starts a new streak, so the
        // first repeat of the new value is duplicate #1 again.
        if sent.acknowledgment != Some(tcp.acknowledgment) || sent.window != Some(tcp.window) {
            sent.duplicate_acks = 0;
        }
        sent.acknowledgment = Some(tcp.acknowledgment);
    }
    true
}
