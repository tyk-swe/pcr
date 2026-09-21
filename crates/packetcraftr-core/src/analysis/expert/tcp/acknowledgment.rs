// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use crate::diagnostic::Severity;

use super::DirectionState;
use crate::analysis::expert::finding::new as new_finding;
use crate::analysis::expert::observation::TcpObservation;
use crate::analysis::expert::{Finding, ScopedFlowKey};
use crate::analysis::serial::{serial_ge, serial_gt};

pub(super) fn observe_duplicate(
    flows: &mut HashMap<ScopedFlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    reverse: &ScopedFlowKey,
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
            peer.payload_next
                .is_some_and(|next| serial_gt(next, tcp.acknowledgment))
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
    flows: &mut HashMap<ScopedFlowKey, DirectionState>,
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
            .is_some_and(|previous| !serial_ge(tcp.acknowledgment, previous));
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
