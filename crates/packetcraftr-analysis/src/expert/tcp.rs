// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use packetcraftr_packet::diagnostic::Severity as DiagnosticSeverity;

use super::finding::new as new_finding;
use super::generation;
use super::observation::TcpObservation;
use super::{ExpertCollector, Finding, FlowKey, FrameRecord, Tcp, TcpEvent};

mod acknowledgment;
mod sequence;
mod window;

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
    /// Mirrors the reassembler's capture base for observed-overlap claims.
    pub(super) reassembly_base: Option<u32>,
    /// Set only after the clean-close frame's header analysis.
    pub(super) closed: bool,
}

impl ExpertCollector {
    pub(super) fn reconcile_tcp_evictions(&mut self, events: &[TcpEvent]) {
        for event in events {
            if let TcpEvent::Evicted { flow, .. } = event
                && let Some(state) = self.flows.get_mut(flow)
            {
                state.reassembly_base = None;
                state.closed = false;
            }
        }
    }

    pub(super) fn observe_tcp(
        &mut self,
        record: &FrameRecord<'_>,
        flow: &FlowKey,
        tcp: &Tcp,
        payload_len: usize,
        findings: &mut Vec<Finding>,
    ) {
        let observation = TcpObservation::new(record, flow, tcp, payload_len);
        let (probe_shape, reassembly_retransmission) =
            sequence::reconcile_events(&mut self.flows, &observation, record.tcp_events, findings);

        if observation.rst {
            findings.push(new_finding(
                DiagnosticSeverity::Warning,
                "tcp.reset",
                observation.number,
                observation.stream,
                format!(
                    "connection reset by {}:{}",
                    observation.flow.source, observation.flow.source_port
                ),
            ));
        }
        window::report_zero(&observation, findings);

        if let Some(stream) = record.tcp_stream {
            self.streams.entry(flow.clone()).or_insert(stream);
        }

        let generation::GenerationTransition {
            reverse,
            syn_renews,
        } = generation::apply(&mut self.flows, &observation);

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
        if acknowledgment::update(&mut self.flows, &observation, syn_renews) {
            window::update_advertisement(&mut self.flows, &observation);
        }

        window::analyze_sender(&self.flows, &observation, &reverse, keep_alive, findings);

        generation::retire_reset(&mut self.flows, &observation, &reverse);
        sequence::record_clean_closures(&mut self.flows, record.tcp_events);
    }
}

pub(super) fn finish(
    streams: &HashMap<FlowKey, u64>,
    events: &[TcpEvent],
    end_number: u64,
) -> Vec<Finding> {
    sequence::finish(streams, events, end_number)
}

pub(super) fn window_scale(options: &[u8]) -> Option<u8> {
    window::scale(options)
}
