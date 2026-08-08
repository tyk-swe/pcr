// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordered TCP expert transition orchestration and shared direction state.

use packetcraftr_packet::diagnostic::DiagnosticSeverity;

use super::finding::new as new_finding;
use super::generation;
use super::observation::TcpObservation;
use super::{ExpertCollector, Finding, FlowKey, FrameRecord, Tcp};

mod acknowledgment;
mod sequence;
mod window;

/// One direction's most recent TCP header facts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DirectionState {
    /// Sequence one past the last unit this direction has sent, control
    /// flags included, matching the peer's SND.NXT view.
    pub(super) next_sequence: Option<u32>,
    /// Sequence one past the last payload byte this direction has sent.
    /// SYN and FIN consume sequence numbers but carry no payload, so this
    /// is what bounds claims about previously seen data.
    pub(super) payload_next: Option<u32>,
    /// Last acknowledgment number this direction announced.
    pub(super) acknowledgment: Option<u32>,
    /// How many identical acknowledgments have repeated, including the first.
    pub(super) duplicate_acks: u64,
    /// Last window this direction advertised, in unscaled wire units.
    pub(super) window: Option<u16>,
    /// Sequence of the segment carrying the last accepted window update —
    /// TCP's SND.WL1 — which orders window updates.
    pub(super) window_sequence: Option<u32>,
    /// Acknowledgment of that segment — TCP's SND.WL2 — which orders
    /// same-sequence updates.
    pub(super) window_acknowledgment: Option<u32>,
    /// Whether that window rode on a SYN, whose window field is never
    /// scaled.
    pub(super) window_from_syn: bool,
    /// Whether this direction's SYN was captured, which is what makes its
    /// window scale — including scale zero — knowable at all.
    pub(super) syn_seen: bool,
    /// Shift this direction's SYN offered in a window-scale option; `None`
    /// when the SYN carried no such option.
    pub(super) window_shift: Option<u8>,
    /// First sequence of the current generation the reassembler could have
    /// observed, mirroring its capture base.
    pub(super) reassembly_base: Option<u32>,
    /// Whether the reassembler completed this direction cleanly — which
    /// proves every byte up to the cursor was delivered — and then forgot
    /// the flow, leaving later retransmissions to the header view here.
    pub(super) closed: bool,
}

impl ExpertCollector {
    pub(super) fn observe_tcp(
        &mut self,
        record: &FrameRecord<'_>,
        flow: &FlowKey,
        tcp: &Tcp,
        payload_len: usize,
        findings: &mut Vec<Finding>,
    ) {
        let observation = TcpObservation::new(record, flow, tcp, payload_len);

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
            record.tcp_events,
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

        // A reset ends the conversation in both directions, so nothing
        // learned about either direction survives it; a later connection
        // over the same endpoints starts from nothing.
        generation::retire_reset(&mut self.flows, &observation, &reverse);
    }
}

pub(super) fn window_scale(options: &[u8]) -> Option<u8> {
    window::scale(options)
}
