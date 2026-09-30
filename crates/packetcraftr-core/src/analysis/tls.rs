// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS handshake assembly over reassembled TCP streams.
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
//! Fingerprints are advisory: every byte they are computed from is chosen by the peer.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::analysis::conversation_index::CanonicalFlow;
use crate::analysis::pipeline::{FrameRecord, Summary as RunSummary};
use crate::analysis::reassembly::tcp::{Event as TcpEvent, ScopedFlowKey};
use crate::analysis::session::{Collector as SessionCollector, CollectorNeeds};
use crate::error::BoundaryError;
use crate::protocol::transport::Tcp;

mod certificates;
mod limits;
pub use certificates::{Certificate, CertificateCollection, CertificateStatus, MAX_CERTIFICATES};
mod live;
mod selector;
mod session;

pub use limits::{Limits, MAX_DIRECTION_BUFFER};
pub use selector::{Selector, SniPattern};
pub use session::{
    ALERT_LEVEL_FATAL, ALERT_LEVEL_WARNING, Alert, ClientSummary, MAX_ALERTS, ServerSummary,
    Session, Status,
};

use live::{Live, Verdict};

/// QUIC's HTTPS port: its TLS 1.3 handshakes are counted, not read.
const QUIC_UDP_PORT: u16 = 443;

const REASON_REASSEMBLY_GAP: &str = "TCP reassembly reported missing handshake bytes";
const REASON_FLOW_EVICTED: &str = "the TCP flow was evicted before the handshake finished";
const REASON_SESSION_LIMIT: &str = "the session table reached its ceiling";
const REASON_AGGREGATE_LIMIT: &str = "the aggregate handshake buffer reached its ceiling";
const REASON_TRUNCATED: &str = "the capture ended while the handshake was in flight";

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SessionEvent {
    /// 1-based capture frame whose arrival ended the session.
    pub number: u64,
    pub session: Session,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub clock: crate::analysis::ClockReport,
    pub sessions: u64,
    pub by_status: BTreeMap<Status, u64>,
    /// TCP conversations this collector saw, whether or not they carried TLS.
    pub tcp_streams: u64,
    pub evicted_sessions: u64,
    pub buffer_limit_hits: u64,
    pub udp_443_frames: u64,
}

#[derive(Debug)]
struct Entry {
    order: u64,
    state: Tracked,
}

#[derive(Debug)]
// Closed + SYN -> absent -> fresh Live/deduplicator. Never reopen from stale buffered bytes.
enum Tracked {
    Live(Box<Live>),
    /// Terminal: new bytes on the four-tuple are ignored until a SYN retires the entry.
    Closed,
}

#[derive(Debug)]
pub struct Collector {
    limits: Limits,
    collect_certificates: bool,
    entries: HashMap<CanonicalFlow, Entry>,
    order: BTreeMap<u64, CanonicalFlow>,
    seen_streams: HashSet<u64>,
    next_order: u64,
    next_session: u64,
    buffered_bytes: usize,
    summary: Summary,
}

impl Collector {
    pub fn new(limits: Limits) -> Result<Self, crate::analysis::Error> {
        limits.validate()?;
        Ok(Self {
            limits,
            collect_certificates: false,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            seen_streams: HashSet::new(),
            next_order: 0,
            next_session: 0,
            buffered_bytes: 0,
            summary: Summary::default(),
        })
    }

    /// Continue plaintext TLS 1.2 server handshakes until the certificate chain.
    #[must_use]
    pub fn with_certificates(mut self) -> Self {
        self.collect_certificates = true;
        self
    }
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        if let Some(conversation) = record.udp.and_then(|view| view.conversation)
            && let flow = conversation.flow
            && (flow.flow.source_port == QUIC_UDP_PORT
                || flow.flow.destination_port == QUIC_UDP_PORT)
        {
            self.summary.udp_443_frames = self.summary.udp_443_frames.saturating_add(1);
        }
        // Expiry and replacement events precede current data and must retain their ordering.
        let current_flow = record
            .tcp
            .and_then(|view| view.conversation)
            .map(|stream| stream.flow);
        let last_data = record.tcp_events.iter().rposition(
            |event| matches!(event, TcpEvent::Data { flow, .. } if Some(flow) == current_flow),
        );
        let deferred_close = last_data.and_then(|data| {
            record
                .tcp_events
                .iter()
                .enumerate()
                .find_map(|(index, event)| {
                    (index > data
                        && matches!(event, TcpEvent::Closed { flow, reset: false }
                    if Some(flow) == current_flow))
                    .then_some(index)
                })
        });
        self.fold_reassembly_events(
            record.tcp_events,
            record.number,
            deferred_close,
            &mut events,
        );

        let Some(tcp) = record.tcp else { return events };
        let Some(conversation) = tcp.conversation else {
            return events;
        };
        let flow = conversation.flow;
        let stream = conversation.index;
        self.note_stream(stream);
        let key = CanonicalFlow::from_flow(flow);
        if tcp.header.flags & Tcp::SYN != 0 {
            self.discard_closed(&key);
        }

        // Tracked from its first frame, payload or not, because that frame elects the client.
        match self.entries.get(&key) {
            Some(Entry {
                state: Tracked::Closed,
                ..
            }) => return events,
            Some(_) => {}
            None => self.track(
                &key,
                stream,
                flow.clone(),
                record
                    .scope_definition(flow.scope)
                    .expect("indexed scope exists")
                    .clone(),
                &mut events,
            ),
        }
        if let Some(live) = self.live_mut(&key) {
            live.note_frame(Some(record.timestamp));
            let first = live.first_flow().clone();
            live.dedup().observe_syn(flow, &first, tcp.header);
        }
        self.fold_deliveries(record, &key, &mut events);
        if let Some(close) = deferred_close.and_then(|index| record.tcp_events.get(index)) {
            self.fold_reassembly_events(
                std::slice::from_ref(close),
                record.number,
                None,
                &mut events,
            );
        }
        events
    }

    #[must_use]
    pub fn finish(mut self, summary: &RunSummary) -> (Vec<SessionEvent>, Summary) {
        let mut events = Vec::new();
        let trailing = &summary.trailing_tcp_events;
        for event in trailing {
            if let TcpEvent::Gap { flow, .. } = event {
                let key = CanonicalFlow::from_flow(flow);
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
        debug_assert_eq!(
            self.buffered_bytes, 0,
            "terminal paths release every handshake charge"
        );
        self.summary.clock = summary.clock.clone();
        self.summary.tcp_streams = self.seen_streams.len() as u64;
        (events, self.summary)
    }

    /// Gap outranks close, which outranks eviction; a reset produces both close and eviction.
    fn fold_reassembly_events(
        &mut self,
        tcp_events: &[TcpEvent],
        number: u64,
        deferred_close: Option<usize>,
        events: &mut Vec<SessionEvent>,
    ) {
        for event in tcp_events {
            if let TcpEvent::Gap { flow, .. } = event {
                let key = CanonicalFlow::from_flow(flow);
                self.retire(
                    &key,
                    Status::Gap,
                    Some(REASON_REASSEMBLY_GAP.to_owned()),
                    number,
                    events,
                );
            }
        }
        for (index, event) in tcp_events.iter().enumerate() {
            if deferred_close == Some(index) {
                continue;
            }
            if let TcpEvent::Closed { flow, reset } = event {
                let key = CanonicalFlow::from_flow(flow);
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
                let key = CanonicalFlow::from_flow(flow);
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

    fn fold_deliveries(
        &mut self,
        record: &FrameRecord<'_>,
        key: &CanonicalFlow,
        events: &mut Vec<SessionEvent>,
    ) {
        let ceiling = MAX_DIRECTION_BUFFER;
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
            let Some(direction) = live.direction_of(sender) else {
                continue;
            };
            let deduplicated = live
                .dedup()
                .deduplicate(direction.dedup(), *sequence, bytes);
            let Some(payload) = deduplicated.filter(|payload| !payload.is_empty()) else {
                continue;
            };
            let Some(charge) = live.retainable(direction, payload.len(), ceiling) else {
                continue;
            };
            live.note_delivery(record.number);

            // Room is made before buffering, so the aggregate ceiling is never exceeded.
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
            let verdict = live.feed(direction, &payload, ceiling, &mut limit_hits);
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

    fn live_mut(&mut self, key: &CanonicalFlow) -> Option<&mut Live> {
        match self.entries.get_mut(key) {
            Some(Entry {
                state: Tracked::Live(live),
                ..
            }) => Some(live),
            _ => None,
        }
    }

    fn last_frame(&self, key: &CanonicalFlow) -> u64 {
        match self.entries.get(key) {
            Some(Entry {
                state: Tracked::Live(live),
                ..
            }) => live.last_frame(),
            _ => 0,
        }
    }

    fn track(
        &mut self,
        key: &CanonicalFlow,
        stream: u64,
        flow: ScopedFlowKey,
        scope: crate::analysis::scope::Definition,
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
                state: Tracked::Live(Box::new(
                    Live::new(stream, flow, scope).with_certificates(self.collect_certificates),
                )),
            },
        );
    }

    /// Filtering can expose older indices after newer ones, in either direction.
    fn note_stream(&mut self, stream: u64) {
        self.seen_streams.insert(stream);
    }

    fn evict_oldest(
        &mut self,
        protect: Option<&CanonicalFlow>,
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

    fn retire(
        &mut self,
        key: &CanonicalFlow,
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

    fn forget(&mut self, key: &CanonicalFlow) {
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
        let session = live.into_session(index, status, reason);
        let by_status = self.summary.by_status.entry(session.status).or_default();
        *by_status = by_status.saturating_add(1);
        events.push(SessionEvent { number, session });
    }

    fn discard(&mut self, key: &CanonicalFlow) {
        if let Some(entry) = self.entries.get_mut(key)
            && let Tracked::Live(live) = std::mem::replace(&mut entry.state, Tracked::Closed)
        {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(live.buffered());
            if !live.is_session() {
                self.forget(key);
            }
        }
    }

    fn discard_closed(&mut self, key: &CanonicalFlow) {
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

impl SessionCollector for Collector {
    type Event = SessionEvent;
    type Summary = Summary;

    /// Without UDP indexes, `udp_443_frames` silently reports zero.
    fn needs(&self) -> CollectorNeeds {
        CollectorNeeds {
            tcp_stream: true,
            udp_stream: true,
            tcp_events: true,
            ..CollectorNeeds::default()
        }
    }

    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<SessionEvent>, BoundaryError> {
        Ok(Self::observe(self, record))
    }

    fn finish(self, run: &RunSummary) -> Result<(Vec<SessionEvent>, Summary), BoundaryError> {
        Ok(Self::finish(self, run))
    }
}
