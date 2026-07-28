// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-frame protocol health findings computed over the analysis pipeline.

use std::collections::{BTreeMap, HashMap};

use packetcraftr_packet::diagnostic::DiagnosticSeverity;

use super::session_index::{transport_payload, transports};
use super::{FlowKey, FrameRecord, Tcp, TcpEvent};

use finding::new as new_finding;
use observation::TcpObservation;

mod finding;
mod generation;
mod observation;

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

/// One direction's most recent TCP header facts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DirectionState {
    /// Sequence one past the last unit this direction has sent, control
    /// flags included, matching the peer's SND.NXT view.
    next_sequence: Option<u32>,
    /// Sequence one past the last payload byte this direction has sent.
    /// SYN and FIN consume sequence numbers but carry no payload, so this
    /// is what bounds claims about previously seen data.
    payload_next: Option<u32>,
    /// Last acknowledgment number this direction announced.
    acknowledgment: Option<u32>,
    /// How many identical acknowledgments have repeated, including the first.
    duplicate_acks: u64,
    /// Last window this direction advertised, in unscaled wire units.
    window: Option<u16>,
    /// Sequence of the segment carrying the last accepted window update —
    /// TCP's SND.WL1 — which orders window updates.
    window_sequence: Option<u32>,
    /// Acknowledgment of that segment — TCP's SND.WL2 — which orders
    /// same-sequence updates.
    window_acknowledgment: Option<u32>,
    /// Whether that window rode on a SYN, whose window field is never
    /// scaled.
    window_from_syn: bool,
    /// Whether this direction's SYN was captured, which is what makes its
    /// window scale — including scale zero — knowable at all.
    syn_seen: bool,
    /// Shift this direction's SYN offered in a window-scale option; `None`
    /// when the SYN carried no such option.
    window_shift: Option<u8>,
    /// First sequence of the current generation the reassembler could have
    /// observed, mirroring its capture base.
    reassembly_base: Option<u32>,
    /// Whether the reassembler completed this direction cleanly — which
    /// proves every byte up to the cursor was delivered — and then forgot
    /// the flow, leaving later retransmissions to the header view here.
    closed: bool,
}

/// Detects cross-frame TCP conditions from dissected headers.
///
/// Retransmission and gap evidence comes from the session reassembler's
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

    fn observe_tcp(
        &mut self,
        record: &FrameRecord<'_>,
        flow: &FlowKey,
        tcp: &Tcp,
        payload_len: usize,
        findings: &mut Vec<Finding>,
    ) {
        let observation = TcpObservation::new(record, flow, tcp, payload_len);
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
        } = observation;
        let mut push = |severity, code: &str, message: String| {
            findings.push(new_finding(severity, code, number, stream, message));
        };

        if rst {
            push(
                DiagnosticSeverity::Warning,
                "tcp.reset",
                format!("connection reset by {}:{}", flow.source, flow.source_port),
            );
        }
        if tcp.window == 0 && !rst {
            push(
                DiagnosticSeverity::Warning,
                "tcp.zero_window",
                format!(
                    "{}:{} advertises a zero receive window",
                    flow.source, flow.source_port
                ),
            );
        }

        if let Some(stream) = record.tcp_stream {
            self.streams.entry(flow.clone()).or_insert(stream);
        }

        let generation::GenerationTransition {
            reverse,
            syn_renews,
        } = generation::apply(&mut self.flows, &observation);
        // Keep-alive: one byte or less, sequenced exactly one before what
        // this direction already sent, with no state-changing flag.
        // Against a peer's closed window the same one-byte shape is the
        // persist probe, which the window analysis below classifies.
        let peer_zero_window = self
            .flows
            .get(&reverse)
            .is_some_and(|peer| peer.window == Some(0));
        let sent = self.flows.entry(flow.clone()).or_default();
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
            push(
                DiagnosticSeverity::Info,
                "tcp.keep_alive",
                format!("{}:{} probes the peer", flow.source, flow.source_port),
            );
        }
        // After a clean close the reassembler has forgotten the flow, so a
        // late retransmission produces no event there; the close proved
        // contiguous delivery, so a data segment wholly inside the closed
        // payload range repeats observed bytes. The payload boundary — not
        // SND.NXT, which counts the FIN's sequence number — is what bounds
        // that claim. The reassembler's byte-exact events stay authoritative
        // whenever it produced any for this flow.
        if !keep_alive
            && sent.closed
            && payload_len > 0
            && !syn
            && let (Some(base), Some(payload_next)) = (sent.reassembly_base, sent.payload_next)
            && tcp.sequence.wrapping_sub(base) < 0x8000_0000
            && !record.tcp_events.iter().any(|event| {
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
                push(
                    DiagnosticSeverity::Warning,
                    "tcp.retransmission",
                    format!(
                        "{payload_len} byte(s) at sequence {} retransmit previously seen data",
                        tcp.sequence
                    ),
                );
            }
        }
        // A sequence-consuming segment — data or a FIN — starting past this
        // direction's expected next sequence means the bytes in between never
        // arrived: lost, still in flight, or reordered; only later frames can
        // tell which.
        if !keep_alive
            && (payload_len > 0 || fin)
            && !syn
            && let Some(next) = sent.next_sequence
            && tcp.sequence != next
            && tcp.sequence.wrapping_sub(next) < 0x8000_0000
        {
            push(
                DiagnosticSeverity::Warning,
                "tcp.previous_segment_not_captured",
                format!(
                    "{}:{} resumes at sequence {} before sequence {next} arrived",
                    flow.source, flow.source_port, tcp.sequence
                ),
            );
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

        // Duplicate acknowledgment: a pure repeat of the previous
        // acknowledgment from the same direction, carrying nothing else. It
        // is loss evidence only while the peer has data outstanding beyond
        // the repeated acknowledgment — a duplicated handshake or teardown
        // acknowledgment repeats nothing in flight. An uncaptured reverse
        // direction stays reportable, since one-sided captures of the
        // acknowledging direction are common. A zero-length keep-alive
        // necessarily repeats the previous acknowledgment and is already
        // reported as the probe it is.
        if ack && payload_len == 0 && !keep_alive && !syn && !fin && !rst {
            // Outstanding means outstanding payload: an unacknowledged SYN
            // or FIN occupies sequence space but repeats no data, so a
            // duplicated teardown acknowledgment stays unreported. A peer
            // that was never captured stays reportable; one that was
            // captured sending only control segments has nothing in flight.
            let outstanding = self.flows.get(&reverse).is_none_or(|peer| {
                peer.payload_next.is_some_and(|next| {
                    let delta = next.wrapping_sub(tcp.acknowledgment);
                    delta > 0 && delta < 0x8000_0000
                })
            });
            let sent = self.flows.entry(flow.clone()).or_default();
            if sent.acknowledgment == Some(tcp.acknowledgment) && sent.window == Some(tcp.window) {
                sent.duplicate_acks += 1;
                let count = sent.duplicate_acks;
                if outstanding {
                    push(
                        DiagnosticSeverity::Warning,
                        "tcp.duplicate_ack",
                        format!(
                            "{}:{} repeats acknowledgment {} (duplicate #{count})",
                            flow.source, flow.source_port, tcp.acknowledgment
                        ),
                    );
                }
            } else {
                sent.duplicate_acks = 0;
            }
        }
        // A SYN advertises a receive window whether or not it acknowledges
        // anything, so window facts are recorded for both. A renewing SYN is
        // a delayed duplicate of the handshake: recording it would roll the
        // acknowledgment and window back behind newer advertisements. It
        // still contributes the first acknowledgment its direction has
        // shown, as when a simultaneous open moves from a pure SYN to a
        // SYN-ACK on the same base.
        if ack || syn {
            let sent = self.flows.entry(flow.clone()).or_default();
            // A reordered or retransmitted segment can carry an older
            // acknowledgment; TCP never moves the acknowledged point
            // backward, so such a segment updates nothing.
            let backward = ack
                && sent.acknowledgment.is_some_and(|previous| {
                    tcp.acknowledgment.wrapping_sub(previous) >= 0x8000_0000
                });
            if !backward && !(syn_renews && sent.acknowledgment.is_some()) {
                if ack {
                    // A changed acknowledgment or window starts a new
                    // streak, so the first repeat of the new value is
                    // duplicate #1 again.
                    if sent.acknowledgment != Some(tcp.acknowledgment)
                        || sent.window != Some(tcp.window)
                    {
                        sent.duplicate_acks = 0;
                    }
                    sent.acknowledgment = Some(tcp.acknowledgment);
                }
                // Window updates are ordered by TCP's SND.WL1/WL2 rule: a
                // newer segment sequence, or the same sequence with an
                // acknowledgment no older than the last update's. A
                // retransmitted older segment never replaces the window,
                // whatever acknowledgment it carries.
                let window_update = match (sent.window_sequence, sent.window_acknowledgment) {
                    (Some(update_sequence), Some(update_acknowledgment)) => {
                        let sequence_delta = tcp.sequence.wrapping_sub(update_sequence);
                        (sequence_delta > 0 && sequence_delta < 0x8000_0000)
                            || (tcp.sequence == update_sequence
                                && tcp.acknowledgment.wrapping_sub(update_acknowledgment)
                                    < 0x8000_0000)
                    }
                    _ => true,
                };
                if window_update {
                    sent.window = Some(tcp.window);
                    sent.window_sequence = Some(tcp.sequence);
                    sent.window_acknowledgment = Some(tcp.acknowledgment);
                    sent.window_from_syn = syn;
                }
            }
        }

        // Window analysis: this direction's data against what the peer last
        // advertised it may accept. A zero window is unaffected by scaling,
        // so it is judged even mid-stream; a positive window is scaled by
        // the handshake's negotiated shift and therefore judged only when
        // both SYNs were captured — without them the scale, and so the real
        // window, is unknowable.
        if (payload_len > 0 || fin)
            && !keep_alive
            && !rst
            && let Some(peer) = self.flows.get(&reverse).copied()
            && let (Some(peer_ack), Some(peer_window)) = (peer.acknowledgment, peer.window)
        {
            // SYN and FIN each consume one sequence number, so a closing
            // data segment can fill the last byte of the window.
            let end = tcp.sequence.wrapping_add(
                u32::try_from(payload_len).unwrap_or(u32::MAX) + u32::from(syn) + u32::from(fin),
            );
            let in_flight = end.wrapping_sub(peer_ack);
            let handshake_seen =
                peer.syn_seen && self.flows.get(flow).is_some_and(|sender| sender.syn_seen);
            // Scaling is in effect only when both SYNs offered it, and the
            // shift that applies to the peer's windows is the one the peer
            // itself advertised, capped as RFC 7323 requires. A window that
            // rode on the SYN itself is never scaled.
            let shift = match (
                self.flows.get(flow).and_then(|sender| sender.window_shift),
                peer.window_shift,
            ) {
                (Some(_), Some(peer_shift)) if !peer.window_from_syn => {
                    u32::from(peer_shift.min(14))
                }
                _ => 0,
            };
            let advertised = u64::from(peer_window) << shift;
            if in_flight < 0x8000_0000 {
                // Reaching the advertised edge exactly is a full window;
                // going past it means the sender overran what the receiver
                // permitted, which is its own condition. Against a zero
                // window, a single new byte at the acknowledged edge is the
                // conventional probe of a closed window, not an overrun.
                if peer_window == 0 {
                    if in_flight > 0 {
                        if payload_len == 1 && !fin && in_flight == 1 {
                            findings.push(new_finding(
                                DiagnosticSeverity::Info,
                                "tcp.zero_window_probe",
                                number,
                                stream,
                                format!(
                                    "{}:{} probes the peer's zero receive window",
                                    flow.source, flow.source_port
                                ),
                            ));
                        } else {
                            findings.push(new_finding(
                                DiagnosticSeverity::Warning,
                                "tcp.window_exceeded",
                                number,
                                stream,
                                format!(
                                    "{}:{} has sent {} byte(s) beyond the peer's zero \
                                     receive window",
                                    flow.source,
                                    flow.source_port,
                                    u64::from(in_flight)
                                ),
                            ));
                        }
                    }
                } else if handshake_seen && u64::from(in_flight) == advertised {
                    findings.push(new_finding(
                        DiagnosticSeverity::Warning,
                        "tcp.window_full",
                        number,
                        stream,
                        format!(
                            "{}:{} has filled the peer's {advertised}-byte receive window",
                            flow.source, flow.source_port
                        ),
                    ));
                } else if handshake_seen && u64::from(in_flight) > advertised {
                    findings.push(new_finding(
                        DiagnosticSeverity::Warning,
                        "tcp.window_exceeded",
                        number,
                        stream,
                        format!(
                            "{}:{} has sent {} byte(s) beyond the peer's {advertised}-byte \
                             receive window",
                            flow.source,
                            flow.source_port,
                            u64::from(in_flight) - advertised
                        ),
                    ));
                }
            }
        }

        // A reset ends the conversation in both directions, so nothing
        // learned about either direction survives it; a later connection
        // over the same endpoints starts from nothing.
        generation::retire_reset(&mut self.flows, &observation, &reverse);
    }
}

/// Extracts the shift a SYN's window-scale option advertises, when present.
///
/// The option list is walked defensively: padding is skipped, and an
/// end-of-options marker or a malformed length ends the walk.
fn window_scale(options: &[u8]) -> Option<u8> {
    let mut rest = options;
    loop {
        match rest {
            [] | [0, ..] => return None,
            [1, tail @ ..] => rest = tail,
            [3, 3, shift, ..] => return Some(*shift),
            [_, length, tail @ ..] if *length >= 2 => {
                rest = tail.get(usize::from(*length) - 2..)?;
            }
            _ => return None,
        }
    }
}
