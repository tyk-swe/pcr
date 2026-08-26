// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS handshake assembly over reassembled TCP streams.
//!
//! One record per handshake, joining a client's offer to a server's decision.
//! The per-frame `tls` layer sees one segment at a time and cannot answer
//! "which version was negotiated" when a ClientHello spans segments; this
//! collector consumes the TCP reassembler's in-order deliveries instead, so a
//! hello split across seven segments produces the same record as an unsplit
//! one.
//!
//! ```text
//!                            Event::Data (per direction, after dedup)
//!                                          │
//!                    ┌─────────────────────▼─────────────────────┐
//!                    │  record framing  ≤ 1 record held unframed │
//!                    │  handshake bodies concatenated per side   │
//!                    │  client: 1 change_cipher_spec skipped     │
//!                    │  server: buffering stops at ServerHello   │
//!                    └─────────────────────┬─────────────────────┘
//!                                          │
//!   ┌──────────────────────────────────────┴──────────────────────────────┐
//!   │                             in flight                               │
//!   └──┬────────────┬─────────────┬────────────┬────────────┬─────────────┘
//!      │            │             │            │            │
//!      │ ServerHello│ HelloRetry  │ fatal      │ unparsable │ Gap/Evicted,
//!      │ (not HRR)  │ then FIN/RST│ alert      │ or buffer  │ ceiling, or
//!      │            │             │            │ ceiling    │ SH with no CH
//!      ▼            ▼             ▼            ▼            ▼
//!   complete      retry         alert      malformed       gap
//!
//!      ClientHello then FIN/RST ─▶ client_only
//!      capture ends in flight   ─▶ truncated
//! ```
//!
//! Orientation follows the same rule as [`follow`](crate::analysis::follow):
//! the client is the sender of the conversation's first captured frame. A
//! capture that starts mid-connection can elect the wrong side, so the first
//! hello re-orients the session once; a second contradiction is `malformed`.
//! Deduplication edges stay bound to the captured direction across that swap,
//! and each session owns one deduplicator, because a four-tuple reused after
//! a clean close is a new session with its own delivery edges.
//!
//! Fingerprints in the assembled record are advisory. Every byte they are
//! computed from is chosen by the peer, so treat a match as a hint about
//! software identity, never as authentication.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::analysis::adapter::transports;
use crate::analysis::dedup::Direction;
use crate::analysis::pipeline::FrameRecord;
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::protocol::transport::Tcp;

mod limits;
mod session;

pub use limits::{Limits, MAX_DIRECTION_BUFFER};
pub use session::{
    ALERT_LEVEL_FATAL, ALERT_LEVEL_WARNING, Alert, ClientSummary, Endpoint, MAX_ALERTS,
    ServerSummary, Session, Status,
};

use session::{Live, Verdict};

/// The UDP port QUIC uses for HTTPS. Frames on it carry TLS 1.3 handshakes
/// this collector deliberately does not read, so they are counted instead of
/// being silently dropped.
const QUIC_UDP_PORT: u16 = 443;

/// Reason strings the collector attaches to non-`complete` sessions.
const REASON_REASSEMBLY_GAP: &str = "TCP reassembly reported missing handshake bytes";
const REASON_FLOW_EVICTED: &str = "the TCP flow was evicted before the handshake finished";
const REASON_SESSION_LIMIT: &str = "the session table reached its ceiling";
const REASON_AGGREGATE_LIMIT: &str = "the aggregate handshake buffer reached its ceiling";
const REASON_TRUNCATED: &str = "the capture ended while the handshake was in flight";

/// One assembled session, delivered as soon as it reaches a terminal status.
///
/// Sessions are emitted progressively so a streaming consumer never has to
/// hold the whole capture's worth of records in memory.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SessionEvent {
    /// 1-based capture frame whose arrival ended the session. The trailing
    /// flush attributes its events to the session's own last frame.
    pub number: u64,
    pub session: Session,
}

/// Terminal counters for a completed session assembly pass.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Sessions emitted, of every status.
    pub sessions: u64,
    /// Sessions per status, in [`Status`] order.
    pub by_status: BTreeMap<Status, u64>,
    /// TCP conversations this collector saw, whether or not they carried TLS.
    /// A capture with streams but no sessions means the traffic was not TLS,
    /// or the handshake itself was not captured. Counted as conversations are
    /// first seen, which the pipeline indexes in first-frame order, so a
    /// four-tuple reused after a close counts once.
    pub tcp_streams: u64,
    /// Sessions retired by a resource ceiling rather than by the capture.
    pub evicted_sessions: u64,
    /// Times one direction's handshake buffer reached its ceiling.
    pub buffer_limit_hits: u64,
    /// UDP frames seen on port 443, which are most likely QUIC. TLS over
    /// QUIC is out of scope, so this is how under-reporting stays visible.
    pub udp_443_frames: u64,
}

/// A tracked conversation.
#[derive(Debug)]
struct Entry {
    /// Insertion rank, used to retire the oldest conversation first.
    order: u64,
    state: Tracked,
}

#[derive(Debug)]
enum Tracked {
    /// A handshake still being assembled.
    Live(Box<Live>),
    /// Terminal: whatever it had to say has been emitted, and new bytes on
    /// the four-tuple are ignored until a SYN retires the entry.
    Closed,
}

/// Assembles TLS sessions from the analysis pipeline's TCP reassembly events.
///
/// Feed every matched frame to [`Collector::observe`] from a run configured
/// with [`Options::tcp_events`](crate::analysis::Options::tcp_events), then
/// close the pass with [`Collector::finish`] and the run summary's trailing
/// events.
#[derive(Debug)]
pub struct Collector {
    limits: Limits,
    entries: HashMap<ScopedFlowKey, Entry>,
    /// Insertion rank to conversation, so the oldest is retired in O(log n).
    order: BTreeMap<u64, ScopedFlowKey>,
    /// Conversations seen, and the highest conversation index behind that
    /// count. Stream indices are handed out in first-frame order, so counting
    /// each rise is counting distinct conversations without a set of them.
    streams: u64,
    highest_stream: Option<u64>,
    next_order: u64,
    next_session: u64,
    buffered_bytes: usize,
    summary: Summary,
}

impl Collector {
    /// Creates a collector bound to finite ceilings.
    ///
    /// Validate the limits with [`Limits::validate`] first if they did not
    /// come from [`Limits::default`]; a zero ceiling here simply retires
    /// every session it touches.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            streams: 0,
            highest_stream: None,
            next_order: 0,
            next_session: 0,
            buffered_bytes: 0,
            summary: Summary::default(),
        }
    }

    /// Folds one matched frame, returning the sessions it ended.
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        if let Some(flow) = record.udp_flow
            && (flow.flow.source_port == QUIC_UDP_PORT
                || flow.flow.destination_port == QUIC_UDP_PORT)
        {
            self.summary.udp_443_frames = self.summary.udp_443_frames.saturating_add(1);
        }
        self.fold_reassembly_events(record.tcp_events, record.number, &mut events);

        let (Some(flow), Some(stream)) = (record.tcp_flow, record.tcp_stream) else {
            return events;
        };
        self.note_stream(stream);
        let key = canonical(flow);
        let transport = transports(&record.decoded.packet).tcp;
        if let Some(transport) = &transport
            && transport.layer.flags & Tcp::SYN != 0
        {
            // A connection opening on a retired four-tuple is a new session,
            // with its own index and its own delivery edges.
            self.discard_closed(&key);
        }

        // A conversation is tracked from its first captured frame, payload or
        // not, because that frame is what elects the client: a capture that
        // starts mid-connection can see the server first, and the elected
        // roles are only corrected once a hello says otherwise.
        match self.entries.get(&key) {
            Some(Entry {
                state: Tracked::Closed,
                ..
            }) => return events,
            Some(_) => {}
            None => self.track(&key, stream, flow.clone(), &mut events),
        }
        if let Some(live) = self.live_mut(&key) {
            live.note_frame(record.decoded.frame.timestamp);
            if let Some(transport) = &transport {
                let first = live.first_flow().clone();
                live.dedup().observe_syn(flow, &first, transport.layer);
            }
        }
        self.fold_deliveries(record, &key, &mut events);
        events
    }

    /// Finishes the pass, folding in the pipeline's trailing flush.
    ///
    /// The flush evicts every flow the capture left open, so an eviction here
    /// is the capture ending rather than data loss: sessions still in flight
    /// are [`truncated`](Status::Truncated), and only a trailing gap — bytes
    /// that were captured but never deliverable — is a [`gap`](Status::Gap).
    #[must_use]
    pub fn finish(mut self, trailing: &[TcpEvent]) -> (Vec<SessionEvent>, Summary) {
        let mut events = Vec::new();
        for event in trailing {
            if let TcpEvent::Gap { flow, .. } = event {
                let key = canonical(flow);
                let number = self.last_frame(&key);
                self.retire(
                    &key,
                    Status::Gap,
                    Some(REASON_REASSEMBLY_GAP.to_owned()),
                    number,
                    &mut events,
                );
            }
        }
        let remaining = self.order.values().cloned().collect::<Vec<_>>();
        for key in remaining {
            let number = self.last_frame(&key);
            self.retire(
                &key,
                Status::Truncated,
                Some(REASON_TRUNCATED.to_owned()),
                number,
                &mut events,
            );
        }
        self.summary.tcp_streams = self.streams;
        (events, self.summary)
    }

    /// Folds the verdicts reassembly reached about tracked flows.
    ///
    /// These ride any frame's expiry sweep, not just the frames of the flow
    /// they concern, so they are folded in before the frame is matched to a
    /// conversation. A gap outranks a close on the same frame — missing bytes
    /// are the stronger statement — and a close outranks an eviction, because
    /// a reset arrives as both and the close is the one that says why.
    fn fold_reassembly_events(
        &mut self,
        tcp_events: &[TcpEvent],
        number: u64,
        events: &mut Vec<SessionEvent>,
    ) {
        for event in tcp_events {
            if let TcpEvent::Gap { flow, .. } = event {
                let key = canonical(flow);
                self.retire(
                    &key,
                    Status::Gap,
                    Some(REASON_REASSEMBLY_GAP.to_owned()),
                    number,
                    events,
                );
            }
        }
        for event in tcp_events {
            if let TcpEvent::Closed { flow, reset } = event {
                let key = canonical(flow);
                let Some(live) = self.live_mut(&key) else {
                    continue;
                };
                if !*reset {
                    let first = live.first_flow().clone();
                    live.dedup().mark_closed(flow, &first);
                }
                let status = live.close_status();
                let Some(status) = status else {
                    self.discard(&key);
                    continue;
                };
                self.retire(&key, status, None, number, events);
            }
        }
        for event in tcp_events {
            if let TcpEvent::Evicted { flow, .. } = event {
                let key = canonical(flow);
                let Some(live) = self.live_mut(&key) else {
                    self.discard_closed(&key);
                    continue;
                };
                let first = live.first_flow().clone();
                live.dedup().mark_evicted(flow, &first);
                self.retire(
                    &key,
                    Status::Gap,
                    Some(REASON_FLOW_EVICTED.to_owned()),
                    number,
                    events,
                );
                self.discard_closed(&key);
            }
        }
    }

    /// Folds this frame's in-order deliveries into the tracked conversation.
    fn fold_deliveries(
        &mut self,
        record: &FrameRecord<'_>,
        key: &ScopedFlowKey,
        events: &mut Vec<SessionEvent>,
    ) {
        let cap = MAX_DIRECTION_BUFFER;
        for event in record.tcp_events {
            let TcpEvent::Data {
                flow: sender,
                sequence,
                bytes,
            } = event
            else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            let Some(live) = self.live_mut(key) else {
                return;
            };
            // A delivery of some other conversation rode this frame's sweep.
            let Some(direction) = live.direction_of(sender) else {
                continue;
            };
            let deduplicated =
                live.dedup()
                    .deduplicate(dedup_direction(direction), *sequence, bytes);
            let Some(payload) = deduplicated.filter(|payload| !payload.is_empty()) else {
                continue;
            };
            // A direction that has stopped contributing handshake bytes keeps
            // none of this delivery, so it charges nothing and the frame is
            // not part of the handshake this session reports.
            let Some(charge) = live.retainable(direction, payload.len(), cap) else {
                continue;
            };
            live.note_delivery(record.number);

            // Room is made before any of the delivery is buffered, so the
            // aggregate ceiling is never exceeded even transiently. Only what
            // the direction can still retain is charged for.
            while self.buffered_bytes.saturating_add(charge) > self.limits.max_buffered_bytes
                && self.evict_oldest(Some(key), REASON_AGGREGATE_LIMIT, events)
            {}
            if self.buffered_bytes.saturating_add(charge) > self.limits.max_buffered_bytes {
                if self.retire(
                    key,
                    Status::Gap,
                    Some(REASON_AGGREGATE_LIMIT.to_owned()),
                    record.number,
                    events,
                ) {
                    self.summary.evicted_sessions = self.summary.evicted_sessions.saturating_add(1);
                }
                return;
            }

            let mut limit_hits = 0;
            let Some(live) = self.live_mut(key) else {
                return;
            };
            let before = live.buffered();
            let verdict = live.feed(direction, &payload, cap, &mut limit_hits);
            let after = live.buffered();
            self.buffered_bytes = self
                .buffered_bytes
                .saturating_sub(before)
                .saturating_add(after);
            self.summary.buffer_limit_hits =
                self.summary.buffer_limit_hits.saturating_add(limit_hits);
            if let Verdict::Finished { status, reason } = verdict {
                self.retire(key, status, reason, record.number, events);
            }
        }
    }

    fn live_mut(&mut self, key: &ScopedFlowKey) -> Option<&mut Live> {
        match self.entries.get_mut(key) {
            Some(Entry {
                state: Tracked::Live(live),
                ..
            }) => Some(live),
            _ => None,
        }
    }

    fn last_frame(&self, key: &ScopedFlowKey) -> u64 {
        match self.entries.get(key) {
            Some(Entry {
                state: Tracked::Live(live),
                ..
            }) => live.last_frame(),
            _ => 0,
        }
    }

    /// Starts tracking a conversation, making room for it first.
    fn track(
        &mut self,
        key: &ScopedFlowKey,
        stream: u64,
        flow: ScopedFlowKey,
        events: &mut Vec<SessionEvent>,
    ) {
        while self.entries.len() >= self.limits.max_sessions {
            if !self.evict_oldest(Some(key), REASON_SESSION_LIMIT, events) {
                break;
            }
        }
        let order = self.next_order;
        self.next_order = self.next_order.saturating_add(1);
        self.order.insert(order, key.clone());
        self.entries.insert(
            key.clone(),
            Entry {
                order,
                state: Tracked::Live(Box::new(Live::new(stream, flow))),
            },
        );
    }

    /// Counts a conversation the first time one of its frames is seen.
    /// Stream indices rise in first-seen order, so a rise is a new
    /// conversation; a caller that filters frames before observing can hide
    /// an earlier conversation's frames and undercount.
    fn note_stream(&mut self, stream: u64) {
        if self.highest_stream.is_none_or(|highest| stream > highest) {
            self.highest_stream = Some(stream);
            self.streams = self.streams.saturating_add(1);
        }
    }

    /// Retires the oldest tracked conversation other than `protect`,
    /// reporting an in-flight handshake as a gap. Returns whether anything
    /// was retired.
    fn evict_oldest(
        &mut self,
        protect: Option<&ScopedFlowKey>,
        reason: &str,
        events: &mut Vec<SessionEvent>,
    ) -> bool {
        let candidate = self
            .order
            .iter()
            .find(|(_, key)| Some(*key) != protect)
            .map(|(order, key)| (*order, key.clone()));
        let Some((order, key)) = candidate else {
            return false;
        };
        self.order.remove(&order);
        let Some(entry) = self.entries.remove(&key) else {
            return true;
        };
        if let Tracked::Live(live) = entry.state {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(live.buffered());
            if live.is_session() {
                self.summary.evicted_sessions = self.summary.evicted_sessions.saturating_add(1);
                let number = live.last_frame();
                self.emit(*live, Status::Gap, Some(reason.to_owned()), number, events);
            }
        }
        true
    }

    /// Ends a tracked handshake, emitting it when it assembled anything.
    ///
    /// A handshake that assembled something leaves the entry behind as closed,
    /// so late bytes on the four-tuple do not manufacture a second session.
    /// One that assembled nothing has nothing to protect and the entry is
    /// dropped instead, so a conversation whose gap arrived before its hello
    /// is tracked again from the next frame. Returns whether a session was
    /// emitted.
    fn retire(
        &mut self,
        key: &ScopedFlowKey,
        status: Status,
        reason: Option<String>,
        number: u64,
        events: &mut Vec<SessionEvent>,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        let Tracked::Live(live) = std::mem::replace(&mut entry.state, Tracked::Closed) else {
            return false;
        };
        self.buffered_bytes = self.buffered_bytes.saturating_sub(live.buffered());
        if !live.is_session() {
            self.forget(key);
            return false;
        }
        self.emit(*live, status, reason, number, events);
        true
    }

    /// Drops an entry and its insertion rank, whatever state it is in.
    fn forget(&mut self, key: &ScopedFlowKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.order.remove(&entry.order);
        }
    }

    fn emit(
        &mut self,
        live: Live,
        status: Status,
        reason: Option<String>,
        number: u64,
        events: &mut Vec<SessionEvent>,
    ) {
        let index = self.next_session;
        self.next_session = self.next_session.saturating_add(1);
        self.summary.sessions = self.summary.sessions.saturating_add(1);
        let by_status = self.summary.by_status.entry(status).or_default();
        *by_status = by_status.saturating_add(1);
        events.push(SessionEvent {
            number,
            session: live.into_session(index, status, reason),
        });
    }

    /// Closes a conversation. One that assembled nothing is forgotten
    /// outright, so a later hello on the same four-tuple is tracked again;
    /// one that did leaves a closed marker until a new connection opens.
    fn discard(&mut self, key: &ScopedFlowKey) {
        if let Some(entry) = self.entries.get_mut(key)
            && let Tracked::Live(live) = std::mem::replace(&mut entry.state, Tracked::Closed)
        {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(live.buffered());
            if !live.is_session() {
                self.forget(key);
            }
        }
    }

    /// Drops a closed entry so the four-tuple can carry a new session.
    fn discard_closed(&mut self, key: &ScopedFlowKey) {
        if matches!(
            self.entries.get(key),
            Some(Entry {
                state: Tracked::Closed,
                ..
            })
        ) {
            self.forget(key);
        }
    }
}

/// The direction-independent identity of a conversation.
fn canonical(flow: &ScopedFlowKey) -> ScopedFlowKey {
    let reverse = flow.reverse();
    if *flow <= reverse {
        flow.clone()
    } else {
        reverse
    }
}

/// The deduplicator's view of a captured direction, which never moves even
/// when the client and server roles are swapped.
fn dedup_direction(direction: usize) -> Direction {
    if direction == 0 {
        Direction::ClientToServer
    } else {
        Direction::ServerToClient
    }
}
