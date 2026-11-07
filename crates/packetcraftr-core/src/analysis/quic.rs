mod crypto;
mod handshake;
mod keylog;
mod model;
mod protection;
mod ranges;
mod state;
mod transport;

use crate::analysis::{FrameRecord, ScopedFlowKey, scope, session};
use crate::error::BoundaryError;
use crate::field::WireValue;
pub use crate::protocol::application::quic::Error;
use crate::protocol::{
    application::quic::{PacketKind, Version, parse_packet},
    identity,
};
use bytes::Bytes;
pub use keylog::{Import, KeyLog};
pub use model::{
    Connection, Diagnostic, Direction, EarlyData, Event, Limits, Metrics, Range, Stream, Summary,
    TransportParameter,
};
use state::{Observation, Pending, PendingReason, State};
use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

type CidIndex = BTreeMap<(u32, Vec<u8>), BTreeSet<(u64, Direction)>>;
type ResetIndex = BTreeMap<(u32, [u8; 16]), BTreeSet<u64>>;

pub struct Datagram<'a> {
    pub number: u64,
    pub timestamp: SystemTime,
    pub flow: &'a ScopedFlowKey,
    pub scope: &'a scope::Definition,
    pub payload: &'a [u8],
    pub source_frames: &'a [u64],
    pub truncated: bool,
}

pub struct Collector {
    limits: Limits,
    keylog: KeyLog,
    refreshed_revision: u64,
    states: BTreeMap<u64, State>,
    cids: CidIndex,
    resets: ResetIndex,
    lru: BTreeSet<(SystemTime, u64)>,
    summary: Summary,
    memory: usize,
    next_connection: u64,
    capture_incomplete: bool,
}
impl Collector {
    pub fn mark_capture_incomplete(&mut self) {
        self.capture_incomplete = true;
        for state in self.states.values_mut() {
            state.report.incomplete = true;
        }
    }
    pub fn new(limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let keylog_limit = (limits.max_buffered_bytes / 4).min(16 * 1024 * 1024);
        Ok(Self {
            limits,
            keylog: KeyLog::with_limit(keylog_limit),
            refreshed_revision: 0,
            states: BTreeMap::new(),
            cids: BTreeMap::new(),
            resets: BTreeMap::new(),
            lru: BTreeSet::new(),
            summary: Summary::default(),
            memory: 0,
            next_connection: 0,
            capture_incomplete: false,
        })
    }
    pub fn append_keylog(&mut self, bytes: &[u8], finish: bool) -> Import {
        let result = self.keylog.append(bytes, finish);
        self.summary.keylog_records_added += result.added;
        self.summary.keylog_records_rejected += result.rejected;
        result
    }
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        if record.decoded.frame.is_truncated() {
            self.mark_capture_incomplete();
        }
        let Some(view) = record.udp else {
            return Ok(Vec::new());
        };
        let Some(conversation) = view.conversation else {
            return Ok(Vec::new());
        };
        let Some(scope) = record.scope_definition(conversation.flow.scope) else {
            return Err(Error::Invalid);
        };
        let Some(WireValue::Exact(length)) = view
            .decoded
            .packet
            .layer(view.layer)
            .and_then(identity::udp_length)
        else {
            return Ok(Vec::new());
        };
        let start = view
            .decoded
            .layout
            .layer(view.layer)
            .ok_or(Error::Invalid)?
            .range
            .end;
        let expected = usize::from(length).saturating_sub(8);
        let bytes = view.decoded.frame.bytes();
        let end = start.saturating_add(expected).min(bytes.len());
        let payload = bytes.get(start..end).ok_or(Error::Truncated)?;
        let frames: Vec<_> = record.udp_sources().map_or_else(
            || vec![record.number],
            |sources| sources.frames().iter().map(|f| f.number).collect(),
        );
        self.ingest(Datagram {
            number: record.number,
            timestamp: record.timestamp,
            flow: conversation.flow,
            scope,
            payload,
            source_frames: &frames,
            truncated: payload.len() != expected,
        })
    }
    pub fn ingest(&mut self, input: Datagram<'_>) -> Result<Vec<Event>, Error> {
        let mut events = Vec::new();
        if input.truncated {
            self.mark_capture_incomplete();
        }
        self.expire(input.timestamp, &mut events);
        let mut offset = 0;
        let mut count = 0;
        while offset < input.payload.len() {
            if count >= self.limits.max_ranges {
                self.summary.malformed_datagrams += 1;
                break;
            }
            count += 1;
            let remaining = &input.payload[offset..];
            let short = remaining[0] & 0x80 == 0;
            let matched = if short {
                self.match_short(input.flow, remaining)
            } else {
                match crate::protocol::application::quic::long_destination_connection_id(remaining)
                {
                    Ok(dcid) => self.match_id(input.flow, dcid),
                    Err(_) => {
                        if input.flow.flow.source_port == 443
                            || input.flow.flow.destination_port == 443
                        {
                            self.summary.malformed_datagrams += 1;
                        }
                        break;
                    }
                }
            };
            let association = match matched {
                Association::One {
                    connection,
                    direction,
                    length,
                } => Some((connection, direction, length)),
                Association::Ambiguous => {
                    self.summary.ambiguous_packets += 1;
                    break;
                }
                Association::None => None,
            };
            let packet = match parse_packet(remaining, association.map(|(_, _, len)| len)) {
                Ok(packet) => packet,
                Err(error) => {
                    if short && self.stateless_reset(&input, remaining) {
                        break;
                    }
                    if association.is_some()
                        || input.flow.flow.source_port == 443
                        || input.flow.flow.destination_port == 443
                    {
                        self.summary.malformed_datagrams += 1;
                    }
                    if let Some((index, _, _)) = association
                        && let Some(mut state) = self.take(index)
                    {
                        state.record_datagram(&input, &self.limits);
                        state.report.metrics.packets += 1;
                        self.summary.packets += 1;
                        state.diagnostic(
                            input.number,
                            "malformed_packet",
                            error.to_string(),
                            &self.limits,
                        );
                        self.store(index, state);
                    }
                    break;
                }
            };
            offset += packet.bytes.len();
            if packet.kind == PacketKind::Unsupported {
                if association.is_some()
                    || input.flow.flow.source_port == 443
                    || input.flow.flow.destination_port == 443
                {
                    self.summary.unsupported_versions += 1;
                }
                if association.is_none() {
                    continue;
                }
            }
            let (index, direction, length) = if let Some(association) = association {
                association
            } else {
                if short && self.stateless_reset(&input, packet.bytes) {
                    continue;
                }
                if packet.kind != PacketKind::Initial {
                    if input.flow.flow.source_port == 443 || input.flow.flow.destination_port == 443
                    {
                        self.summary.unassociated_packets += 1;
                    }
                    continue;
                }
                let Some(version) = Version::from_wire(packet.version) else {
                    continue;
                };
                let keys = crypto::Keys::initial(version, packet.dcid, true)?;
                if keys.open(&packet, None).is_err() {
                    self.summary.unassociated_packets += 1;
                    continue;
                }
                while self.states.len() >= self.limits.max_connections {
                    self.evict("connection_limit", &mut events);
                }
                let index = self.next_connection;
                self.next_connection += 1;
                let mut state = State::new(index, version, &input, &packet);
                state.report.incomplete |= self.capture_incomplete;
                self.summary.connections += 1;
                self.store(index, state);
                (index, Direction::Client, packet.dcid.len())
            };
            let mut state = self.take(index).ok_or(Error::Invalid)?;
            self.summary.packets += 1;
            state.record_datagram(&input, &self.limits);
            let before = state.report.metrics.decrypted_packets;
            let mut result = state.process(
                &packet,
                &Observation {
                    direction,
                    number: input.number,
                    timestamp: input.timestamp,
                    flow: &input.flow.flow,
                },
                &self.keylog,
                &self.limits,
                false,
            );
            if short
                && packet.bytes.len() >= 21
                && matches!(result, Ok(false) | Err(Error::Authentication))
                && state.cids.iter().any(|cid| {
                    !cid.retired
                        && cid.owner == direction
                        && cid
                            .token
                            .is_some_and(|token| packet.bytes.ends_with(&token))
                })
            {
                state.report.stateless_reset = true;
                state.report.closed = true;
                result = Ok(true);
            }
            self.handle_result(
                &mut state,
                result,
                Pending {
                    reason: PendingReason::MissingSecrets,
                    bytes: Bytes::copy_from_slice(packet.bytes),
                    direction,
                    dcid_length: length,
                    number: input.number,
                    timestamp: input.timestamp,
                    flow: input.flow.flow.clone(),
                    keylog_revision: self.keylog.revision(),
                },
            );
            self.retry(&mut state);
            self.summary.decrypted_packets += state.report.metrics.decrypted_packets - before;
            self.store(index, state);
            self.enforce_memory(&mut events);
        }
        self.enforce_memory(&mut events);
        Ok(events)
    }
    fn enforce_memory(&mut self, events: &mut Vec<Event>) {
        while self.memory.saturating_add(self.keylog.memory()) > self.limits.max_buffered_bytes
            && !self.states.is_empty()
        {
            self.summary.buffer_limit_hits += 1;
            self.evict("buffer_limit", events);
        }
    }
    fn handle_result(&self, state: &mut State, result: Result<bool, Error>, pending: Pending) {
        match result {
            Ok(true) => {}
            Ok(false) => self.defer(state, pending),
            Err(Error::Authentication) => {
                state.report.metrics.authentication_failures += 1;
                if pending.bytes.first().is_some_and(|b| b & 0x80 == 0) {
                    self.defer(
                        state,
                        Pending {
                            reason: PendingReason::Authentication,
                            ..pending
                        },
                    );
                } else {
                    state.diagnostic(
                        pending.number,
                        "authentication_failed",
                        "QUIC packet authentication failed",
                        &self.limits,
                    );
                }
            }
            Err(error) => {
                let code = match error {
                    Error::Limit => "buffer_limit",
                    Error::UnsupportedFrame(_) => "unsupported_frame",
                    _ => "malformed_packet",
                };
                state.diagnostic(pending.number, code, error.to_string(), &self.limits);
            }
        }
    }
    fn defer(&self, state: &mut State, pending: Pending) {
        if state.pending.len() >= self.limits.max_pending_packets {
            state.pending.pop_front();
            state.diagnostic(
                pending.number,
                "pending_limit",
                "Encrypted packet buffering limit reached",
                &self.limits,
            );
        }
        state.pending.push_back(pending);
    }
    fn retry(&self, state: &mut State) {
        if state.key_revision == self.keylog.revision() && !state.context_changed {
            return;
        }
        state.key_revision = self.keylog.revision();
        state.context_changed = false;
        for _ in 0..self.limits.max_pending_packets {
            let mut progressed = false;
            let pending = std::mem::take(&mut state.pending);
            for mut item in pending {
                let Ok(packet) = parse_packet(&item.bytes, Some(item.dcid_length)) else {
                    continue;
                };
                let result = state.process(
                    &packet,
                    &Observation {
                        direction: item.direction,
                        number: item.number,
                        timestamp: item.timestamp,
                        flow: &item.flow,
                    },
                    &self.keylog,
                    &self.limits,
                    true,
                );
                if result == Err(Error::Authentication)
                    && item.reason != PendingReason::Authentication
                {
                    state.report.metrics.authentication_failures += 1;
                }
                match result {
                    Ok(false) | Err(Error::Authentication) => {
                        item.reason = if result.is_err() {
                            PendingReason::Authentication
                        } else {
                            PendingReason::MissingSecrets
                        };
                        item.keylog_revision = self.keylog.revision();
                        state.pending.push_back(item);
                    }
                    Ok(true) => progressed = true,
                    Err(error) => {
                        state.diagnostic(
                            item.number,
                            "packet_decode",
                            error.to_string(),
                            &self.limits,
                        );
                        progressed = true;
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        state.context_changed = false;
    }
    pub fn refresh<F>(
        &mut self,
        deadline: &crate::budget::Deadline,
        mut sink: F,
    ) -> Result<(), BoundaryError>
    where
        F: FnMut(Event) -> Result<(), BoundaryError>,
    {
        session::check(deadline)?;
        let revision = self.keylog.revision();
        if self.refreshed_revision == revision {
            return Ok(());
        }
        let indexes: Vec<_> = self.states.keys().copied().collect();
        for index in indexes {
            crate::analysis::session::check(deadline)?;
            let Some(mut state) = self.take(index) else {
                continue;
            };
            let before = state.report.metrics.decrypted_packets;
            self.retry(&mut state);
            crate::analysis::session::check(deadline)?;
            self.summary.decrypted_packets += state.report.metrics.decrypted_packets - before;
            self.store(index, state);
            let mut events = Vec::new();
            self.enforce_memory(&mut events);
            for event in events {
                sink(event)?;
            }
        }
        self.refreshed_revision = revision;
        Ok(())
    }
    pub fn finish<F>(
        mut self,
        deadline: &crate::budget::Deadline,
        mut sink: F,
    ) -> Result<Summary, BoundaryError>
    where
        F: FnMut(Event) -> Result<(), BoundaryError>,
    {
        self.refresh(deadline, |event| {
            session::check(deadline)?;
            sink(event)
        })?;
        while let Some(index) = self.states.keys().next().copied() {
            session::check(deadline)?;
            if let Some(state) = self.take(index) {
                sink(Event::Connection {
                    connection: Box::new(state.finish("capture_end", &self.limits)),
                })?;
            }
        }
        Ok(self.summary)
    }
    fn store(&mut self, index: u64, state: State) {
        let scope = state.report.scope.id.get();
        for cid in &state.cids {
            self.cids
                .entry((scope, cid.id.clone()))
                .or_default()
                .insert((index, cid.owner.reverse()));
            if !cid.retired
                && let Some(token) = cid.token
            {
                self.resets.entry((scope, token)).or_default().insert(index);
            }
        }
        self.lru.insert((state.last_time, index));
        self.memory = self.memory.saturating_add(state.memory());
        self.states.insert(index, state);
    }
    fn take(&mut self, index: u64) -> Option<State> {
        let state = self.states.remove(&index)?;
        let scope = state.report.scope.id.get();
        for cid in &state.cids {
            let key = (scope, cid.id.clone());
            if let Some(entries) = self.cids.get_mut(&key) {
                entries.remove(&(index, cid.owner.reverse()));
                if entries.is_empty() {
                    self.cids.remove(&key);
                }
            }
            if let Some(token) = cid.token {
                let key = (scope, token);
                if let Some(entries) = self.resets.get_mut(&key) {
                    entries.remove(&index);
                    if entries.is_empty() {
                        self.resets.remove(&key);
                    }
                }
            }
        }
        self.lru.remove(&(state.last_time, index));
        self.memory = self.memory.saturating_sub(state.memory());
        Some(state)
    }
    fn expire(&mut self, now: SystemTime, events: &mut Vec<Event>) {
        while let Some(&(time, _)) = self.lru.first() {
            if !now
                .duration_since(time)
                .is_ok_and(|idle| idle >= self.limits.idle_expiry)
            {
                break;
            }
            self.evict("idle_expiry", events);
        }
    }
    fn evict(&mut self, reason: &str, events: &mut Vec<Event>) {
        let Some(&(_, index)) = self.lru.first() else {
            return;
        };
        let Some(mut state) = self.take(index) else {
            return;
        };
        let before = state.report.metrics.decrypted_packets;
        self.retry(&mut state);
        self.summary.decrypted_packets += state.report.metrics.decrypted_packets - before;
        if reason != "idle_expiry" {
            self.summary.connections_evicted += 1;
            state.diagnostic(
                state.report.last_frame,
                reason,
                "Connection retired because its analysis resource limit was reached",
                &self.limits,
            );
        }
        events.push(Event::Connection {
            connection: Box::new(state.finish(reason, &self.limits)),
        });
    }
    fn match_id(&self, flow: &ScopedFlowKey, id: &[u8]) -> Association {
        let Some(candidates) = self.cids.get(&(flow.scope.get(), id.to_vec())) else {
            return Association::None;
        };
        let matches: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|(index, direction)| {
                if !id.is_empty() {
                    return true;
                }
                self.states.get(index).is_some_and(|s| {
                    s.report.paths.iter().any(|path| {
                        if *direction == Direction::Client {
                            *path == flow.flow
                        } else {
                            path.reverse() == flow.flow
                        }
                    })
                })
            })
            .collect();
        self.choose(flow, &matches, id.len())
    }
    fn choose(
        &self,
        flow: &ScopedFlowKey,
        matches: &[(u64, Direction)],
        length: usize,
    ) -> Association {
        match matches {
            [] => Association::None,
            [(connection, direction)] => Association::One {
                connection: *connection,
                direction: *direction,
                length,
            },
            _ => {
                let exact: Vec<_> = matches
                    .iter()
                    .copied()
                    .filter(|(id, dir)| {
                        self.states.get(id).is_some_and(|s| {
                            s.report.paths.iter().any(|p| {
                                if *dir == Direction::Client {
                                    *p == flow.flow
                                } else {
                                    p.reverse() == flow.flow
                                }
                            })
                        })
                    })
                    .collect();
                if let [(connection, direction)] = exact.as_slice() {
                    Association::One {
                        connection: *connection,
                        direction: *direction,
                        length,
                    }
                } else {
                    Association::Ambiguous
                }
            }
        }
    }
    fn match_short(&self, flow: &ScopedFlowKey, bytes: &[u8]) -> Association {
        let mut found = Vec::new();
        for length in 0..=20 {
            let Some(id) = bytes.get(1..1 + length) else {
                break;
            };
            match self.match_id(flow, id) {
                Association::One {
                    connection,
                    direction,
                    ..
                } => found.push((connection, direction, length)),
                Association::Ambiguous => return Association::Ambiguous,
                Association::None => {}
            }
        }
        found.sort_unstable();
        found.dedup();
        match found.as_slice() {
            [] => Association::None,
            [(connection, direction, length)] => Association::One {
                connection: *connection,
                direction: *direction,
                length: *length,
            },
            _ => Association::Ambiguous,
        }
    }
    fn stateless_reset(&mut self, input: &Datagram<'_>, bytes: &[u8]) -> bool {
        if bytes.len() < 21 || bytes.first().is_none_or(|first| first & 0xc0 != 0x40) {
            return false;
        }
        let Ok(token) = <[u8; 16]>::try_from(&bytes[bytes.len() - 16..]) else {
            return false;
        };
        let Some(entries) = self.resets.get(&(input.flow.scope.get(), token)) else {
            return false;
        };
        if entries.len() != 1 {
            return false;
        }
        let Some(&index) = entries.first() else {
            return false;
        };
        let Some(mut state) = self.take(index) else {
            return false;
        };
        state.record_datagram(input, &self.limits);
        state.report.metrics.packets += 1;
        self.summary.packets += 1;
        state.report.stateless_reset = true;
        state.report.closed = true;
        self.store(index, state);
        true
    }
}
#[derive(Clone, Copy)]
enum Association {
    None,
    Ambiguous,
    One {
        connection: u64,
        direction: Direction,
        length: usize,
    },
}

impl session::Collector for Collector {
    type Event = Event;
    type Summary = Summary;
    fn needs(&self) -> session::CollectorNeeds {
        session::CollectorNeeds {
            udp_stream: true,
            ip_reassembly: true,
            track_sources: true,
            ..session::CollectorNeeds::default()
        }
    }
    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, BoundaryError> {
        Self::observe(self, record).map_err(BoundaryError::from_error)
    }
    fn finish(
        mut self,
        run: &crate::analysis::Summary,
        deadline: &crate::budget::Deadline,
        sink: &mut dyn FnMut(Event) -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        if run.input_incomplete() {
            self.mark_capture_incomplete();
        }
        Self::finish(self, deadline, sink)
    }
}

#[cfg(test)]
mod tests;
