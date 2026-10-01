// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use crate::diagnostic::Severity;

use super::finding::new as new_finding;
use super::generation;
use super::observation::TcpObservation;
use super::{Collector, Finding, FrameRecord, ScopedFlowKey, TcpEvent};

mod acknowledgment;
mod handshake;
mod sequence;
mod window;

pub(super) use handshake::Prior;
pub(super) use window::scale as window_scale;

/// Reports end-of-capture conditions: residue still awaiting earlier data, unanswered
/// handshakes and established connections that never closed.
pub(super) fn finish(
    flows: &HashMap<ScopedFlowKey, DirectionState>,
    streams: &HashMap<ScopedFlowKey, u64>,
    events: &[TcpEvent],
    end_number: u64,
) -> Vec<Finding> {
    let mut findings = sequence::finish(streams, events, end_number);
    findings.extend(handshake::finish(flows, streams, events, end_number));
    findings
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DirectionState {
    pub(super) next_sequence: Option<u32>,
    pub(super) payload_next: Option<u32>,
    pub(super) acknowledgment: Option<u32>,
    pub(super) duplicate_acks: u64,
    pub(super) window: Option<u16>,
    pub(super) window_sequence: Option<u32>,
    pub(super) window_acknowledgment: Option<u32>,
    pub(super) window_from_syn: bool,
    pub(super) syn_seen: bool,
    pub(super) window_shift: Option<u8>,
    pub(super) reassembly_base: Option<u32>,
    /// Set only after the clean-close frame's header analysis.
    pub(super) closed: bool,
    /// The gaps this direction skipped over and has not fully filled.
    holes: sequence::Holes,
    /// Sequence position of this direction's first FIN in the current generation.
    fin_sequence: Option<u32>,
    /// Set once a fast retransmission answered the current duplicate-ACK streak.
    fast_retransmit_reported: bool,
    handshake: handshake::State,
}

impl DirectionState {
    /// This direction opened a connection whose SYN has no matching SYN-ACK yet.
    pub(super) fn awaiting_syn_ack(&self) -> bool {
        self.handshake.pending()
    }
}

impl Collector {
    pub(super) fn reconcile_tcp_evictions(&mut self, events: &[TcpEvent]) {
        for event in events {
            if let TcpEvent::Evicted { flow, .. } = event
                && let Some(state) = self.flows.get_mut(flow)
            {
                state.reassembly_base = None;
                state.closed = false;
                state.holes = sequence::Holes::default();
                state.fin_sequence = None;
                state.handshake = handshake::State::default();
            }
        }
    }

    pub(super) fn observe_tcp(
        &mut self,
        record: &FrameRecord<'_>,
        conversation: crate::analysis::Conversation<'_>,
        tcp: crate::analysis::TcpView<'_>,
        prior: handshake::Prior,
        findings: &mut Vec<Finding>,
    ) {
        let flow = conversation.flow;
        let observation = TcpObservation::new(record.number, conversation, tcp);
        let (probe_shape, reassembly_retransmission) =
            sequence::reconcile_events(&mut self.flows, &observation, record.tcp_events, findings);

        let handshake::Inspection { refused, mismatch } =
            handshake::inspect(&prior, &observation, findings);
        if observation.rst && !refused {
            findings.push(new_finding(
                Severity::Warning,
                "tcp.reset",
                observation.number,
                observation.stream,
                format!(
                    "connection reset by {}:{}",
                    observation.flow.flow.source, observation.flow.flow.source_port
                ),
            ));
        }
        window::report_zero(&observation, findings);

        self.streams
            .entry(flow.clone())
            .or_insert(conversation.index);

        let generation::GenerationTransition {
            reverse,
            syn_renews,
        } = generation::apply(&mut self.flows, &observation);
        handshake::record(
            &mut self.flows,
            &observation,
            &reverse,
            syn_renews,
            mismatch,
            findings,
        );

        let keep_alive = sequence::observe(
            &mut self.flows,
            &observation,
            &reverse,
            probe_shape,
            reassembly_retransmission,
            findings,
        );

        acknowledgment::observe_duplicate(
            &mut self.flows,
            &observation,
            &reverse,
            keep_alive,
            findings,
        );
        acknowledgment::observe_unseen(&self.flows, &observation, &reverse, keep_alive, findings);
        let previous_acknowledgment = self.flows.get(flow).and_then(|sent| sent.acknowledgment);
        if acknowledgment::update(&mut self.flows, &observation, syn_renews) {
            window::update_advertisement(
                &mut self.flows,
                &observation,
                previous_acknowledgment,
                keep_alive,
                findings,
            );
        }

        window::analyze_sender(&self.flows, &observation, &reverse, keep_alive, findings);

        generation::retire_reset(&mut self.flows, &observation, &reverse);
        sequence::record_clean_closures(&mut self.flows, record.tcp_events);
    }
}
