// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use crate::diagnostic::Severity;

use super::DirectionState;
use crate::analysis::expert::finding::new as new_finding;
use crate::analysis::expert::observation::TcpObservation;
use crate::analysis::expert::{Finding, FlowKey};

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

    if ack && payload_len == 0 && !keep_alive && !syn && !fin && !rst {
        let outstanding = flows.get(reverse).is_some_and(|peer| {
            peer.payload_next.is_some_and(|next| {
                let delta = next.wrapping_sub(tcp.acknowledgment);
                delta > 0 && delta < 0x8000_0000
            })
        });
        let sent = flows.entry(flow.clone()).or_default();
        if outstanding
            && sent.acknowledgment == Some(tcp.acknowledgment)
            && sent.window == Some(tcp.window)
        {
            sent.duplicate_acks = sent.duplicate_acks.saturating_add(1);
            let count = sent.duplicate_acks;
            findings.push(new_finding(
                Severity::Warning,
                "tcp.duplicate_ack",
                number,
                stream,
                format!(
                    "{}:{} repeats acknowledgment {} (duplicate #{count})",
                    flow.flow.source, flow.flow.source_port, tcp.acknowledgment
                ),
            ));
        } else {
            sent.duplicate_acks = 0;
        }
    }
}

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
    // Acknowledgments advance with TCP serial arithmetic.
    let backward = ack
        && sent
            .acknowledgment
            .is_some_and(|previous| tcp.acknowledgment.wrapping_sub(previous) >= 0x8000_0000);
    if backward || (syn_renews && sent.acknowledgment.is_some()) {
        return false;
    }

    if ack {
        if sent.acknowledgment != Some(tcp.acknowledgment) || sent.window != Some(tcp.window) {
            sent.duplicate_acks = 0;
        }
        sent.acknowledgment = Some(tcp.acknowledgment);
    }
    true
}
