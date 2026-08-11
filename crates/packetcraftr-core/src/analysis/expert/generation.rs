// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use super::tcp::{DirectionState, window_scale};
use super::{FlowKey, observation::TcpObservation};

pub(super) struct GenerationTransition {
    pub(super) reverse: FlowKey,
    pub(super) syn_renews: bool,
}

pub(super) fn apply(
    flows: &mut HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
) -> GenerationTransition {
    let TcpObservation {
        flow,
        tcp,
        payload_len,
        syn,
        ack,
        ..
    } = observation;
    let reverse = flow.reverse();
    let mut syn_renews = false;
    if *syn {
        let first = tcp.sequence.wrapping_add(1);
        let reverse_range_verdict =
            flows
                .get(&reverse)
                .and_then(|peer| match (peer.reassembly_base, peer.next_sequence) {
                    (Some(base), Some(next)) => Some(
                        tcp.acknowledgment.wrapping_sub(base) < 0x8000_0000
                            && next.wrapping_sub(tcp.acknowledgment) < 0x8000_0000,
                    ),
                    _ => None,
                });
        let peer_acknowledged = !*ack || reverse_range_verdict != Some(false);
        let sent = flows.entry((*flow).clone()).or_default();
        let renews = sent.reassembly_base == Some(first)
            && !sent.closed
            && peer_acknowledged
            && (*ack || *payload_len > 0 || sent.payload_next.is_none());
        syn_renews = renews;
        if !renews {
            *sent = DirectionState::default();
        }
        sent.syn_seen = true;
        if !renews {
            sent.window_shift = window_scale(tcp.options.as_ref());
        }
        sent.reassembly_base = Some(first);
        if !renews {
            let peer_is_current = if *ack {
                reverse_range_verdict == Some(true)
            } else {
                flows.get(&reverse).is_none_or(|peer| {
                    peer.syn_seen
                        && peer.next_sequence == peer.reassembly_base
                        && peer.acknowledgment.is_none()
                })
            };
            if !peer_is_current {
                flows.remove(&reverse);
            }
        }
    }

    let sent = flows.entry((*flow).clone()).or_default();
    if !*syn
        && sent.reassembly_base.is_none()
        && (*payload_len > 0 || observation.fin || observation.rst)
    {
        sent.reassembly_base = Some(tcp.sequence);
    }

    GenerationTransition {
        reverse,
        syn_renews,
    }
}

pub(super) fn retire_reset(
    flows: &mut HashMap<FlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    reverse: &FlowKey,
) {
    if observation.rst {
        flows.remove(observation.flow);
        flows.remove(reverse);
    }
}
