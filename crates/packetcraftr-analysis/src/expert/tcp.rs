// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cross-frame TCP expert state and observation.

use packetcraftr_packet::diagnostic::DiagnosticSeverity;

use super::finding::new as new_finding;
use super::generation;
use super::observation::TcpObservation;
use super::{ExpertCollector, Finding, FlowKey, FrameRecord, Tcp, TcpEvent};

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
pub(super) fn window_scale(options: &[u8]) -> Option<u8> {
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
