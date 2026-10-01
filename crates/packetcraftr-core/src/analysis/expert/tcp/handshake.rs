// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet};

use crate::diagnostic::Severity;

use super::DirectionState;
use crate::analysis::expert::finding::new as new_finding;
use crate::analysis::expert::observation::TcpObservation;
use crate::analysis::expert::{Finding, ScopedFlowKey, TcpEvent, tcp_stream_ref};
use crate::analysis::serial::{serial_offset, serial_range_contains};

/// Handshake progress one direction contributes within the current generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct State {
    /// Initial sequence number of the pure SYN this direction opened the connection with.
    syn_sequence: Option<u32>,
    /// Set on the opening direction once a SYN-ACK came back.
    answered: bool,
    /// Set on the opening direction once it acknowledged the SYN-ACK.
    established: bool,
}

impl State {
    /// A SYN went out and no matching SYN-ACK has come back yet.
    pub(super) fn pending(self) -> bool {
        self.syn_sequence.is_some() && !self.answered
    }
}

/// Both directions of a frame's flow as they stood before its own evictions apply.
///
/// An idle expiry the same frame triggers is indistinguishable from the evictions a reset or
/// mismatch causes, so a reset or SYN-ACK arriving after the expiry is still judged against
/// the SYN it follows.
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::analysis::expert) struct Prior {
    own: DirectionState,
    peer: DirectionState,
}

impl Prior {
    pub(in crate::analysis::expert) fn capture(
        flows: &HashMap<ScopedFlowKey, DirectionState>,
        flow: &ScopedFlowKey,
    ) -> Self {
        Self {
            own: flows.get(flow).copied().unwrap_or_default(),
            peer: flows.get(&flow.reverse()).copied().unwrap_or_default(),
        }
    }
}

pub(super) struct Inspection {
    /// The frame is a reset answering a handshake segment, reported as a refusal.
    pub(super) refused: bool,
    /// A SYN-ACK that missed the pending SYN it answers, with the handshake that SYN keeps.
    pub(super) mismatch: Option<State>,
}

/// Judges a frame against the handshake state that preceded it.
pub(super) fn inspect(
    prior: &Prior,
    observation: &TcpObservation<'_>,
    findings: &mut Vec<Finding>,
) -> Inspection {
    let TcpObservation {
        number,
        stream,
        flow,
        tcp,
        syn,
        rst,
        ack,
        ..
    } = *observation;

    let mut mismatch = None;
    if syn
        && ack
        && !rst
        && let Some(isn) = prior.peer.handshake.syn_sequence
    {
        let expected = isn.wrapping_add(1);
        // A SYN carrying data may be acknowledged anywhere up to the end of that data.
        let accepted = serial_range_contains(
            Some(expected),
            prior.peer.next_sequence.or(Some(expected)),
            tcp.acknowledgment,
        );
        if accepted == Some(false) {
            mismatch = Some(prior.peer.handshake).filter(|opener| opener.pending());
            findings.push(new_finding(
                Severity::Warning,
                "tcp.synack_mismatch",
                number,
                stream,
                format!(
                    "{}:{} acknowledges sequence {} ({:+} from the {expected} the SYN from {}:{} expects)",
                    flow.flow.source,
                    flow.flow.source_port,
                    tcp.acknowledgment,
                    serial_offset(tcp.acknowledgment, expected),
                    flow.flow.destination,
                    flow.flow.destination_port
                ),
            ));
        }
    }

    let mut refused = false;
    if rst && !syn {
        let peer = prior.peer.handshake;
        let own = prior.own.handshake;
        let answers_syn = peer.syn_sequence.is_some()
            && !peer.answered
            && (!ack
                || serial_range_contains(
                    peer.syn_sequence.map(|isn| isn.wrapping_add(1)),
                    prior.peer.next_sequence,
                    tcp.acknowledgment,
                ) != Some(false));
        let answers_synack = own.syn_sequence.is_some() && own.answered && !own.established;
        if answers_syn || answers_synack {
            refused = true;
            let what = if answers_syn { "SYN" } else { "SYN-ACK" };
            findings.push(new_finding(
                Severity::Warning,
                "tcp.connection_refused",
                number,
                stream,
                format!(
                    "{}:{} reset the {what} exchanged with {}:{}",
                    flow.flow.source,
                    flow.flow.source_port,
                    flow.flow.destination,
                    flow.flow.destination_port
                ),
            ));
        }
    }
    Inspection { refused, mismatch }
}

/// Folds a frame into the handshake state once the generation has been decided.
///
/// A SYN-ACK that missed its pending SYN leaves that SYN pending, although the reassembler
/// evicted the opener's flow in response.
pub(super) fn record(
    flows: &mut HashMap<ScopedFlowKey, DirectionState>,
    observation: &TcpObservation<'_>,
    reverse: &ScopedFlowKey,
    syn_renews: bool,
    mismatch: Option<State>,
    findings: &mut Vec<Finding>,
) {
    let TcpObservation {
        number,
        stream,
        flow,
        tcp,
        syn,
        rst,
        ack,
        ..
    } = *observation;
    if rst {
        return;
    }

    if syn && ack {
        if let Some(pending) = mismatch {
            flows.entry(reverse.clone()).or_default().handshake = pending;
        } else if let Some(opener) = flows
            .get_mut(reverse)
            .filter(|opener| opener.handshake.syn_sequence.is_some())
        {
            opener.handshake.answered = true;
        }
    } else if syn {
        let sent = flows.entry(flow.clone()).or_default();
        if syn_renews && sent.handshake.syn_sequence == Some(tcp.sequence) {
            findings.push(new_finding(
                Severity::Warning,
                "tcp.syn_retransmission",
                number,
                stream,
                format!(
                    "{}:{} resends the SYN with initial sequence {}",
                    flow.flow.source, flow.flow.source_port, tcp.sequence
                ),
            ));
        } else {
            sent.handshake = State {
                syn_sequence: Some(tcp.sequence),
                ..State::default()
            };
        }
    } else if ack {
        let sent = flows.entry(flow.clone()).or_default();
        if sent.handshake.syn_sequence.is_some() && sent.handshake.answered {
            sent.handshake.established = true;
        }
    }
}

/// Reports handshakes still pending and connections still open when the capture ends.
///
/// Flows the reassembler evicted mid-capture lost their handshake state in
/// `reconcile_tcp_evictions`, so only flows live at the end can report here.
pub(super) fn finish(
    flows: &HashMap<ScopedFlowKey, DirectionState>,
    streams: &HashMap<ScopedFlowKey, u64>,
    events: &[TcpEvent],
    end_number: u64,
) -> Vec<Finding> {
    let mut openers = flows
        .iter()
        .filter(|(_, state)| state.handshake.syn_sequence.is_some())
        .map(|(flow, state)| {
            let index = streams.get(flow).or_else(|| streams.get(&flow.reverse()));
            (index.copied(), flow, state)
        })
        .collect::<Vec<_>>();
    openers.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));

    // Looked up once per established flow, so the scan does not grow with the opener count.
    let unfinished = events
        .iter()
        .filter_map(|event| match event {
            TcpEvent::Evicted {
                flow,
                pending_bytes,
            } if *pending_bytes > 0 => Some(flow),
            _ => None,
        })
        .collect::<HashSet<_>>();

    let mut findings = Vec::new();
    for (index, flow, state) in openers {
        let stream = index.map(tcp_stream_ref);
        let source = format!("{}:{}", flow.flow.source, flow.flow.source_port);
        if !state.handshake.answered {
            findings.push(new_finding(
                Severity::Warning,
                "tcp.handshake_unanswered",
                end_number,
                stream,
                format!("the SYN from {source} never received a SYN-ACK"),
            ));
            continue;
        }
        if !state.handshake.established {
            continue;
        }
        let reverse = flow.reverse();
        let closing = state.fin_sequence.is_some()
            || flows
                .get(&reverse)
                .is_some_and(|peer| peer.fin_sequence.is_some());
        let incomplete = unfinished.contains(flow) || unfinished.contains(&reverse);
        if !closing && !incomplete {
            findings.push(new_finding(
                Severity::Info,
                "tcp.not_closed_at_end",
                end_number,
                stream,
                format!("the connection opened by {source} never saw a FIN or RST"),
            ));
        }
    }
    findings
}
