// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-frame protocol health findings computed over the analysis pipeline.

use std::collections::{BTreeMap, HashMap};

use packetcraftr_packet::diagnostic::DiagnosticSeverity;

use super::conversation_index::{transport_payload, transports};
use super::{FlowKey, FrameRecord, Tcp, TcpEvent};

use finding::new as new_finding;
use tcp::DirectionState;

mod finding;
mod generation;
mod observation;
mod tcp;

/// The transport namespace a conversation index belongs to.
///
/// TCP and UDP indices are allocated independently, so a bare number cannot
/// name a conversation in a capture that holds both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamTransport {
    Tcp,
    Udp,
}

/// One conversation: its transport namespace plus per-transport index,
/// matching the `tcp.stream` and `udp.stream` filter vocabularies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamRef {
    pub transport: StreamTransport,
    pub index: u64,
}

const fn tcp_stream_ref(index: u64) -> StreamRef {
    StreamRef {
        transport: StreamTransport::Tcp,
        index,
    }
}

const fn udp_stream_ref(index: u64) -> StreamRef {
    StreamRef {
        transport: StreamTransport::Udp,
        index,
    }
}

/// One expert finding, attributed to the frame that revealed it.
///
/// Findings are cross-frame observations — a retransmission only exists
/// relative to an earlier segment — so they carry their own model rather
/// than the per-frame, layer-scoped decode diagnostics; decode diagnostics
/// are folded in as findings of their own code and severity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: DiagnosticSeverity,
    /// Stable machine-readable code, such as `tcp.retransmission`.
    pub code: String,
    /// 1-based capture frame number that revealed the condition.
    pub number: u64,
    /// The conversation concerned, when there is one.
    pub stream: Option<StreamRef>,
    pub message: String,
}

/// Per-severity and per-code totals for a completed pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpertSummary {
    pub findings: u64,
    pub errors: u64,
    pub warnings: u64,
    pub notes: u64,
    /// Total findings per code, in code order.
    pub codes: BTreeMap<String, u64>,
}

impl ExpertSummary {
    fn count(&mut self, finding: &Finding) {
        self.findings += 1;
        match finding.severity {
            DiagnosticSeverity::Error => self.errors += 1,
            DiagnosticSeverity::Warning => self.warnings += 1,
            DiagnosticSeverity::Info => self.notes += 1,
        }
        *self.codes.entry(finding.code.clone()).or_default() += 1;
    }
}

/// Detects cross-frame TCP conditions from dissected headers.
///
/// Retransmission and gap evidence comes from the reassembly engine's
/// sequence tracking, delivered through the pipeline's TCP events; the
/// header-derived conditions here — duplicate acknowledgment, zero window,
/// window full, keep-alive, reset — need acknowledgment and window fields
/// reassembly deliberately does not carry.
#[derive(Debug, Default)]
pub struct ExpertCollector {
    flows: HashMap<FlowKey, DirectionState>,
    /// Conversation index per directional flow, retained so end-of-capture
    /// findings can still name the stream they belong to.
    streams: HashMap<FlowKey, u64>,
    summary: ExpertSummary,
}

impl ExpertCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one matched frame, returning the findings it revealed.
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();
        let frame_transports = transports(&record.decoded.packet);
        // Dissection problems the decoder already diagnosed — malformed
        // layers, checksum mismatches, bounded-chain warnings — surface as
        // findings under their own codes. A tunnelled frame belongs to both
        // a UDP conversation (the tunnel) and a TCP conversation (the
        // payload), split at the outer transport: headers up to and
        // including it carry the outer conversation, and everything it
        // encapsulates — the inner network headers included — belongs to
        // the inner one. Only the innermost occurrence of each transport is
        // indexed, so in a same-transport tunnel the headers at or above an
        // even-outer occurrence name a conversation without an index; they,
        // like a diagnostic naming no layer at all, name no conversation.
        let indexed_boundary = {
            let indexed_outer = [
                frame_transports.tcp.as_ref().map(|(index, _, _)| *index),
                frame_transports.udp.as_ref().map(|(index, _)| *index),
            ]
            .into_iter()
            .flatten()
            .min();
            match (frame_transports.outermost, indexed_outer) {
                (Some(outermost), Some(indexed)) if outermost < indexed => Some(outermost),
                _ => None,
            }
        };
        for diagnostic in &record.decoded.diagnostics {
            let unindexed_outer_header = indexed_boundary
                .is_some_and(|boundary| diagnostic.layer.is_none_or(|layer| layer <= boundary));
            let stream = if unindexed_outer_header {
                None
            } else {
                match (record.tcp_stream, record.udp_stream) {
                    (Some(stream), None) => Some(tcp_stream_ref(stream)),
                    (None, Some(stream)) => Some(udp_stream_ref(stream)),
                    (None, None) => None,
                    (Some(tcp_stream), Some(udp_stream)) => {
                        match (&frame_transports.tcp, &frame_transports.udp) {
                            (Some((tcp_index, _, _)), Some((udp_index, _))) => {
                                diagnostic.layer.map(|layer| {
                                    let (outer_index, outer_stream, inner_stream) =
                                        if tcp_index < udp_index {
                                            (
                                                *tcp_index,
                                                tcp_stream_ref(tcp_stream),
                                                udp_stream_ref(udp_stream),
                                            )
                                        } else {
                                            (
                                                *udp_index,
                                                udp_stream_ref(udp_stream),
                                                tcp_stream_ref(tcp_stream),
                                            )
                                        };
                                    if layer <= outer_index {
                                        outer_stream
                                    } else {
                                        inner_stream
                                    }
                                })
                            }
                            _ => None,
                        }
                    }
                }
            };
            findings.push(new_finding(
                diagnostic.severity,
                diagnostic.code.clone(),
                record.number,
                stream,
                diagnostic.message.clone(),
            ));
        }

        let frame_tcp = frame_transports.tcp;
        let frame_payload_len = frame_tcp.as_ref().map_or(0, |(index, _, _)| {
            transport_payload(record.decoded, *index).len()
        });
        // A keep-alive probe deliberately re-sends one byte below the
        // cursor, so the reassembler reports it as overlap — conflicting,
        // even, since the probe byte may be garbage. It is not a
        // retransmission; the probe itself is reported by the header view.
        // Keep-alives exist only in synchronized state, so a probe always
        // carries ACK.
        let keep_alive_probe = frame_tcp.as_ref().is_some_and(|(_, flow, tcp)| {
            frame_payload_len <= 1
                && tcp.flags & Tcp::ACK != 0
                && tcp.flags & (Tcp::SYN | Tcp::FIN | Tcp::RST) == 0
                && self.flows.get(flow).is_some_and(|state| {
                    // A direction that sent its FIN probes nothing; a
                    // one-byte segment there is a leftover, not a probe.
                    !state.closed
                        && state
                            .next_sequence
                            .is_some_and(|next| tcp.sequence.wrapping_add(1) == next)
                })
        });
        // A reset's payload is explanatory diagnostic text, not stream
        // data, so its overlap with delivered bytes is no retransmission.
        let reset_frame = frame_tcp
            .as_ref()
            .is_some_and(|(_, _, tcp)| tcp.flags & Tcp::RST != 0);

        // The reassembler's byte-exact sequence tracking is the authority on
        // retransmission, including content that changed under retransmit.
        // Its gap events fire only when a flow is torn down, so hole
        // detection is done per frame from header state below instead.
        for event in record.tcp_events {
            // An evicted flow — idle expiry or generation replacement — is
            // re-anchored by the reassembler at the next segment it sees.
            // The observation base must follow: bytes between the old
            // delivery point and the new anchor were never captured, and
            // events are ordered, so an eviction preceding this frame's own
            // push clears the base before the push's events are read.
            if let TcpEvent::Evicted { flow, .. } = event
                && let Some(state) = self.flows.get_mut(flow)
            {
                state.reassembly_base = None;
                state.closed = false;
            }
            if let TcpEvent::Retransmission {
                flow,
                sequence,
                bytes,
                conflicting,
            } = event
            {
                if keep_alive_probe || reset_frame {
                    continue;
                }
                // The reassembler counts bytes preceding its capture base as
                // retransmitted — for delivery they are equally old — but a
                // mid-stream capture never observed them, so claiming they
                // were seen before would be false. The event's count spans
                // this frame's segment, which starts at the event sequence
                // and carries the frame's payload; the portion of that
                // segment below the base is subtracted before reporting. A
                // flow with no recorded base has no observation to repeat.
                let Some(base) = self.flows.get(flow).and_then(|state| state.reassembly_base)
                else {
                    continue;
                };
                let start = *sequence;
                let length = u32::try_from(frame_payload_len).unwrap_or(u32::MAX);
                let base_delta = base.wrapping_sub(start);
                let pre_base = if base_delta < 0x8000_0000 {
                    base_delta.min(length)
                } else {
                    0
                };
                let observed = u64::try_from(*bytes)
                    .unwrap_or(u64::MAX)
                    .saturating_sub(u64::from(pre_base));
                if observed == 0 {
                    continue;
                }
                // Only a segment that overlapped in its entirety describes a
                // contiguous range; a partial overlap need not start at the
                // segment's first byte, so it is reported as a count within
                // the segment.
                let placement = if pre_base == 0 && *bytes == frame_payload_len {
                    "at sequence"
                } else {
                    "within the segment at sequence"
                };
                findings.push(new_finding(
                    if *conflicting {
                        DiagnosticSeverity::Error
                    } else {
                        DiagnosticSeverity::Warning
                    },
                    if *conflicting {
                        "tcp.retransmission_conflicting"
                    } else {
                        "tcp.retransmission"
                    },
                    record.number,
                    record.tcp_stream.map(tcp_stream_ref),
                    format!(
                        "{observed} byte(s) {placement} {start} retransmit previously seen data{}",
                        if *conflicting {
                            " with different content"
                        } else {
                            ""
                        }
                    ),
                ));
            }
        }

        if let Some((_, flow, tcp)) = frame_tcp {
            self.observe_tcp(record, &flow, tcp, frame_payload_len, &mut findings);
        }

        // A clean close proves contiguous delivery up to the cursor and
        // makes the reassembler forget the flow, so retransmissions arriving
        // afterwards produce no events there; recording the close lets the
        // header view report them. It is recorded only after this frame's
        // own checks, because a close this frame completed says nothing
        // about the frame's own bytes — they may be first arrivals filling
        // the final gap. A reset tears the flow down without that delivery
        // proof, so it grants the header view nothing.
        for event in record.tcp_events {
            if let TcpEvent::Closed { flow, reset: false } = event {
                self.flows.entry(flow.clone()).or_default().closed = true;
            }
        }

        for finding in &findings {
            self.summary.count(finding);
        }
        findings
    }

    /// Finishes the pass, folding in the pipeline's trailing reassembly
    /// events: a flow flushed with bytes still buffered never healed its
    /// holes, which is evidence the per-frame view cannot carry. Returned
    /// findings are attributed to `end_number`, the last frame read.
    pub fn finish(
        mut self,
        trailing: &[super::TcpEvent],
        end_number: u64,
    ) -> (Vec<Finding>, ExpertSummary) {
        let mut findings = Vec::new();
        for event in trailing {
            if let TcpEvent::Evicted {
                flow,
                pending_bytes,
            } = event
                && *pending_bytes > 0
            {
                findings.push(new_finding(
                    DiagnosticSeverity::Info,
                    "tcp.incomplete_at_end",
                    end_number,
                    self.streams
                        .get(flow)
                        .or_else(|| self.streams.get(&flow.reverse()))
                        .copied()
                        .map(tcp_stream_ref),
                    format!(
                        "{} byte(s) from {}:{} were still awaiting missing earlier data \
                         when the capture ended",
                        pending_bytes, flow.source, flow.source_port
                    ),
                ));
            }
        }
        for finding in &findings {
            self.summary.count(finding);
        }
        (findings, self.summary)
    }
}
