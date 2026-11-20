// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Constraint, FrameRecord, ScopedFlowKey, provenance::SourceSet,
    reassembly::tcp::Event as TcpEvent, scope::Definition, serial::serial_offset,
};
use crate::{
    error::{Classification, Classified, Kind},
    protocol::transport::Tcp,
};
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const MAX_BODY_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_messages: usize,
    /// Distinct transport streams the collector may track over the whole run;
    /// a closed stream still counts.
    pub max_streams: usize,
    pub max_buffer_bytes: usize,
    /// Cumulative byte charge for retained and emitted evidence over the
    /// run.
    pub max_retained_bytes: usize,
    pub max_source_spans: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_messages: 4096,
            max_streams: 1024,
            max_buffer_bytes: 16 * 1024 * 1024,
            max_retained_bytes: 64 * 1024 * 1024,
            max_source_spans: 16384,
        }
    }
}
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Analysis(#[from] super::Error),
    #[error(transparent)]
    Provenance(#[from] super::provenance::Error),
    #[error("application analysis exceeds {field}={limit}")]
    Limit { field: &'static str, limit: usize },
    #[error("application stream lacks physical source evidence at frame {number}")]
    Sources { number: u64 },
    #[error("{protocol:?} is not a supported TCP message protocol")]
    Protocol { protocol: String },
    #[error("application event output failed")]
    Output(#[source] crate::error::BoundaryError),
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Analysis(source) => source.classification(),
            Self::Provenance(source) => source.classification(),
            Self::Output(source) => source.classification(),
            Self::Protocol { .. } => Classification::new(
                crate::error::Code::AnalysisMessageProtocol,
                Kind::Usage,
                Some("select a protocol with stream_decode support in reference protocols"),
            ),
            Self::Limit { .. } => Classification::new(
                crate::error::Code::PolicyApplicationLimit,
                Kind::Policy,
                Some("raise a finite application-analysis limit or narrow the capture"),
            ),
            Self::Sources { .. } => Classification::new(
                crate::error::Code::InternalApplicationSources,
                Kind::Internal,
                Some("enable sourced analysis and preserve contributing transport frames"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Analysis(source) => source.causes(),
            Self::Output(source) => source.as_causes(),
            error => crate::error::source_chain(error),
        }
    }
}
impl Limits {
    /// Rejects a zero limit and one above its fixed ceiling.
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value, maximum) in [
            ("max_messages", self.max_messages, 100_000),
            ("max_streams", self.max_streams, 100_000),
            ("max_buffer_bytes", self.max_buffer_bytes, 256 * 1024 * 1024),
            (
                "max_retained_bytes",
                self.max_retained_bytes,
                256 * 1024 * 1024,
            ),
            ("max_source_spans", self.max_source_spans, 100_000),
        ] {
            super::error::check_ceiling(field, value as u64, maximum as u64)?;
        }
        Ok(())
    }

    /// Conservative expansion charge for one decoded object, counted against
    /// `max_retained_bytes`; name compression can expand past it.
    const fn decoded_charge(bytes: usize) -> usize {
        bytes.saturating_mul(32).saturating_add(4096)
    }

    /// Refuses a new stream once `tracked` streams already fill the limit.
    pub(crate) fn check_streams(&self, tracked: usize) -> Result<(), Error> {
        refuse_if(tracked >= self.max_streams, "max_streams", self.max_streams)
    }

    /// Refuses a new message once `seen` messages already fill the limit.
    pub(crate) fn check_messages(&self, seen: usize) -> Result<(), Error> {
        refuse_if(seen >= self.max_messages, "max_messages", self.max_messages)
    }

    pub(crate) fn check_buffer(&self, bytes: usize) -> Result<(), Error> {
        refuse_if(
            bytes > self.max_buffer_bytes,
            "max_buffer_bytes",
            self.max_buffer_bytes,
        )
    }

    pub(crate) fn check_source_spans(&self, spans: usize) -> Result<(), Error> {
        refuse_if(
            spans > self.max_source_spans,
            "max_source_spans",
            self.max_source_spans,
        )
    }

    fn check_retained(&self, total: usize) -> Result<(), Error> {
        refuse_if(
            total > self.max_retained_bytes,
            "max_retained_bytes",
            self.max_retained_bytes,
        )
    }
}

#[derive(Debug)]
pub(crate) struct Retained {
    total: usize,
    limits: Limits,
}

impl Retained {
    pub(crate) const fn new(limits: Limits) -> Self {
        Self { total: 0, limits }
    }

    pub(crate) fn charge(&mut self, bytes: usize) -> Result<(), Error> {
        self.charge_amount(Limits::decoded_charge(bytes))
    }

    pub(crate) fn charge_amount(&mut self, amount: usize) -> Result<(), Error> {
        let total = self.total.saturating_add(amount);
        self.limits.check_retained(total)?;
        self.total = total;
        Ok(())
    }
}

fn refuse_if(exceeded: bool, field: &'static str, limit: usize) -> Result<(), Error> {
    if exceeded {
        return Err(Error::Limit { field, limit });
    }
    Ok(())
}

pub(crate) const MAX_SERVICE_PORTS: usize = 256;

pub(crate) fn normalize_ports(
    ports: impl IntoIterator<Item = u16>,
    field: &'static str,
) -> Result<Vec<u16>, Error> {
    let mut ports: Vec<u16> = ports.into_iter().collect();
    ports.sort_unstable();
    ports.dedup();
    let (value, reason) = if ports.first().is_none_or(|port| *port == 0) {
        (0, Constraint::NonEmptyNonZeroPorts)
    } else if ports.len() > MAX_SERVICE_PORTS {
        (
            ports.len() as u64,
            Constraint::AtMost {
                maximum: MAX_SERVICE_PORTS as u64,
            },
        )
    } else {
        return Ok(ports);
    };
    Err(super::Error::InvalidLimit {
        field,
        value,
        reason,
    }
    .into())
}

#[derive(Clone, Debug)]
pub(crate) struct Delivery {
    pub flow: ScopedFlowKey,
    pub stream: u64,
    pub generation: u64,
    pub bytes: Bytes,
    pub sources: SourceSet,
}
#[derive(Clone, Debug)]
pub(crate) enum Event {
    Data(Delivery),
    Gap {
        flow: ScopedFlowKey,
        stream: u64,
        generation: u64,
    },
    Conflict {
        flow: ScopedFlowKey,
        stream: u64,
        generation: u64,
    },
    Closed {
        flow: ScopedFlowKey,
        stream: u64,
        generation: u64,
        reset: bool,
    },
    Evicted {
        flow: ScopedFlowKey,
        stream: u64,
        generation: u64,
    },
}
#[derive(Clone)]
struct Span {
    sequence: u32,
    length: u32,
    number: u64,
    sources: SourceSet,
}

struct FlowSpans {
    anchor_sequence: u32,
    anchor_offset: i128,
    ranges: BTreeMap<i128, Span>,
}

impl FlowSpans {
    fn new(sequence: u32) -> Self {
        Self {
            anchor_sequence: sequence,
            anchor_offset: 0,
            ranges: BTreeMap::new(),
        }
    }

    fn offset(&self, sequence: u32) -> i128 {
        self.anchor_offset + i128::from(serial_offset(sequence, self.anchor_sequence))
    }

    fn overlapping(&self, start: i128, end: i128) -> impl Iterator<Item = (&i128, &Span)> {
        self.ranges
            .range(..start)
            .next_back()
            .inspect(|_| {
                #[cfg(test)]
                SPANS_VISITED.with(|count| count.set(count.get() + 1));
            })
            .filter(move |(offset, span)| **offset + i128::from(span.length) > start)
            .into_iter()
            .chain(self.ranges.range(start..end).inspect(|_| {
                #[cfg(test)]
                SPANS_VISITED.with(|count| count.set(count.get() + 1));
            }))
    }
}

#[cfg(test)]
thread_local! {
    static SPANS_VISITED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RESET_FLOWS_VISITED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
/// A payload span awaiting insertion; `after` is the index of the frame's
/// reassembly event it must follow, or `None` to precede them all.
struct Incoming {
    flow: ScopedFlowKey,
    span: Span,
    after: Option<usize>,
}

#[cfg(test)]
mod tests;

pub(crate) struct TcpSources {
    ports: Vec<u16>,
    limits: Limits,
    spans: HashMap<ScopedFlowKey, FlowSpans>,
    span_count: usize,
    streams: HashMap<ScopedFlowKey, u64>,
    stream_flows: HashMap<u64, HashSet<ScopedFlowKey>>,
    generations: HashMap<u64, u64>,
    syns: HashMap<ScopedFlowKey, u32>,
    closed: HashSet<ScopedFlowKey>,
    scopes: std::collections::BTreeMap<u32, Definition>,
}
impl TcpSources {
    pub(crate) fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.scopes.values()
    }

    pub(crate) fn generation(&self, stream: u64) -> Option<u64> {
        self.generations.get(&stream).copied()
    }

    pub(crate) fn new(ports: Vec<u16>, limits: Limits) -> Self {
        Self {
            ports,
            limits,
            spans: HashMap::new(),
            span_count: 0,
            streams: HashMap::new(),
            stream_flows: HashMap::new(),
            generations: HashMap::new(),
            syns: HashMap::new(),
            closed: HashSet::new(),
            scopes: Default::default(),
        }
    }
    pub(crate) fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        let mut output = Vec::new();
        let previous_generation = record.tcp.and_then(|view| view.conversation).map(|c| {
            (
                c.index,
                self.generations.get(&c.index).copied().unwrap_or(0),
            )
        });
        let mut incoming = self.admit(record, &mut output)?;
        let previous_generation = previous_generation.filter(|(stream, generation)| {
            self.generations
                .get(stream)
                .is_some_and(|current| current != generation)
        });
        if let Some(incoming) = incoming.take_if(|incoming| incoming.after.is_none()) {
            self.insert(incoming.flow, incoming.span)?;
        }
        // A reset evicts both directions before it closes them, and that close
        // already ends whatever the evictions would have.
        let resets: Vec<&ScopedFlowKey> = record
            .tcp_events
            .iter()
            .filter_map(|event| match event {
                TcpEvent::Closed { flow, reset: true } if self.streams.contains_key(flow) => {
                    Some(flow)
                }
                _ => None,
            })
            .collect();
        for (index, event) in record.tcp_events.iter().enumerate() {
            match event {
                TcpEvent::Evicted { flow, .. }
                    if resets
                        .iter()
                        .any(|reset| *reset == flow || reset.reverse() == *flow) =>
                {
                    self.forget_spans(flow);
                }
                _ => self.event(event, record.number, previous_generation, &mut output)?,
            }
            if let Some(incoming) = incoming.take_if(|incoming| incoming.after == Some(index)) {
                self.insert(incoming.flow, incoming.span)?;
            }
        }
        Ok(output)
    }
    fn admit(
        &mut self,
        record: &FrameRecord<'_>,
        output: &mut Vec<Event>,
    ) -> Result<Option<Incoming>, Error> {
        let Some(view) = record.tcp else {
            return Ok(None);
        };
        let Some(conversation) = view.conversation else {
            return Ok(None);
        };
        let flow = conversation.flow;
        if !self.ports.contains(&flow.flow.source_port)
            && !self.ports.contains(&flow.flow.destination_port)
        {
            return Ok(None);
        }
        if !self.generations.contains_key(&conversation.index) {
            self.limits.check_streams(self.generations.len())?;
        }
        self.generations.entry(conversation.index).or_insert(0);
        self.associate(flow.clone(), conversation.index);
        let last_stream_eviction = record.tcp_events.iter().rposition(|event| {
            matches!(event, TcpEvent::Evicted { flow: expired, .. }
                if self.streams.get(expired) == Some(&conversation.index))
        });
        if let Some(scope) = record.scope_definition(flow.scope) {
            self.scopes
                .entry(scope.id.get())
                .or_insert_with(|| scope.clone());
        }
        let syn = view.header.flags & Tcp::SYN != 0;
        let initial_syn = syn && view.header.flags & Tcp::ACK == 0;
        // Reassembly can prove tuple reuse from sequence state even
        // when this collector sees only the new connection's SYN-ACK.
        let reassembly_reused = syn && last_stream_eviction.is_some();
        let observed_reused = initial_syn
            && (self
                .syns
                .get(flow)
                .is_some_and(|sequence| *sequence != view.header.sequence)
                || (self.closed.contains(flow) && self.closed.contains(&flow.reverse())));
        if reassembly_reused || observed_reused {
            self.reset_stream(conversation.index);
            if !reassembly_reused {
                output.push(Event::Evicted {
                    flow: flow.clone(),
                    stream: conversation.index,
                    generation: self.generations[&conversation.index] - 1,
                });
            }
        }
        if initial_syn {
            self.syns.insert(flow.clone(), view.header.sequence);
            self.closed.remove(flow);
        }
        // The pipeline drops a reset's payload before reassembly, so no
        // delivery would ever consume this span.
        if view.payload.is_empty() || view.header.flags & Tcp::RST != 0 {
            return Ok(None);
        }
        let sources = record
            .tcp_sources()
            .ok_or(Error::Sources {
                number: record.number,
            })?
            .clone();
        Ok(Some(Incoming {
            flow: flow.clone(),
            span: Span {
                sequence: view
                    .header
                    .sequence
                    .wrapping_add(u32::from(view.header.flags & Tcp::SYN != 0)),
                length: u32::try_from(view.payload.len()).map_err(|_| Error::Sources {
                    number: record.number,
                })?,
                number: record.number,
                sources,
            },
            after: last_stream_eviction,
        }))
    }
    pub(crate) fn trailing(
        &mut self,
        events: &[TcpEvent],
        number: u64,
    ) -> Result<Vec<Event>, Error> {
        let mut output = Vec::new();
        for event in events {
            self.event(event, number, None, &mut output)?;
        }
        Ok(output)
    }
    #[cfg(test)]
    pub(super) fn associate_test(&mut self, flow: ScopedFlowKey, stream: u64) {
        self.generations.entry(stream).or_insert(0);
        self.associate(flow, stream);
    }

    fn associate(&mut self, flow: ScopedFlowKey, stream: u64) {
        if let Some(old) = self.streams.insert(flow.clone(), stream)
            && old != stream
            && let Some(flows) = self.stream_flows.get_mut(&old)
        {
            flows.remove(&flow);
            if flows.is_empty() {
                self.stream_flows.remove(&old);
            }
        }
        self.stream_flows.entry(stream).or_default().insert(flow);
    }

    fn reset_stream(&mut self, stream: u64) {
        *self.generations.entry(stream).or_insert(0) += 1;
        if let Some(flows) = self.stream_flows.get(&stream) {
            for flow in flows {
                #[cfg(test)]
                RESET_FLOWS_VISITED.with(|count| count.set(count.get() + 1));
                if let Some(spans) = self.spans.remove(flow) {
                    self.span_count -= spans.ranges.len();
                }
                self.closed.remove(flow);
            }
        }
    }
    fn forget_spans(&mut self, flow: &ScopedFlowKey) {
        if let Some(spans) = self.spans.remove(flow) {
            self.span_count -= spans.ranges.len();
        }
    }
    fn insert(&mut self, flow: ScopedFlowKey, span: Span) -> Result<(), Error> {
        let previous = self.spans.get(&flow);
        let start = previous.map_or(0, |spans| spans.offset(span.sequence));
        let end = start + i128::from(span.length);
        let mut cursor = start;
        let mut pieces = Vec::new();
        if let Some(previous) = previous {
            for (&old_start, old) in previous.overlapping(start, end) {
                if cursor < old_start {
                    pieces.push((cursor, old_start.min(end)));
                }
                cursor = cursor.max(old_start + i128::from(old.length));
            }
        }
        if cursor < end {
            pieces.push((cursor, end));
        }
        self.limits
            .check_source_spans(self.span_count.saturating_add(pieces.len()))?;
        self.span_count += pieces.len();
        if !pieces.is_empty() {
            let ranges = &mut self
                .spans
                .entry(flow)
                .or_insert_with(|| FlowSpans::new(span.sequence))
                .ranges;
            for (piece_start, piece_end) in pieces {
                ranges.insert(
                    piece_start,
                    Span {
                        sequence: span.sequence.wrapping_add((piece_start - start) as u32),
                        length: (piece_end - piece_start) as u32,
                        ..span.clone()
                    },
                );
            }
        }
        Ok(())
    }
    fn event(
        &mut self,
        event: &TcpEvent,
        number: u64,
        previous_generation: Option<(u64, u64)>,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let flow = match event {
            TcpEvent::Data { flow, .. }
            | TcpEvent::Retransmission { flow, .. }
            | TcpEvent::Gap { flow, .. }
            | TcpEvent::Closed { flow, .. }
            | TcpEvent::Evicted { flow, .. } => flow,
        };
        let Some(&stream) = self.streams.get(flow) else {
            return Ok(());
        };
        // A tuple-reuse SYN can evict old bytes before delivering the new generation.
        let generation = previous_generation
            .filter(|(previous, _)| *previous == stream)
            .map_or(self.generations[&stream], |(_, generation)| generation);
        match event {
            TcpEvent::Data {
                sequence, bytes, ..
            } => {
                let length = u32::try_from(bytes.len()).map_err(|_| Error::Sources { number })?;
                let parts = self.spans.get(flow).map(|spans| {
                    let start = spans.offset(*sequence);
                    let end = start + i128::from(length);
                    spans
                        .overlapping(start, end)
                        .map(|(&offset, span)| {
                            (
                                (offset.max(start) - start) as usize,
                                ((offset + i128::from(span.length)).min(end) - start) as usize,
                                span.sources.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                });
                let mut consumed = 0usize;
                for (lo, hi, sources) in parts.into_iter().flatten() {
                    if lo != consumed {
                        return Err(Error::Sources { number });
                    }
                    output.push(Event::Data(Delivery {
                        flow: flow.clone(),
                        stream,
                        generation: self.generations[&stream],
                        bytes: bytes.slice(lo..hi),
                        sources,
                    }));
                    consumed = hi;
                }
                if consumed != bytes.len() {
                    return Err(Error::Sources { number });
                }
                self.subtract(flow, *sequence, length, None)?;
                if let Some(spans) = self.spans.get_mut(flow) {
                    spans.anchor_offset = spans.offset(*sequence) + i128::from(length);
                    spans.anchor_sequence = sequence.wrapping_add(length);
                }
            }
            TcpEvent::Retransmission {
                ranges,
                conflicting,
                ..
            } => {
                for range in ranges {
                    self.subtract(
                        flow,
                        range.start,
                        range.end.wrapping_sub(range.start),
                        Some(number),
                    )?;
                }
                if *conflicting {
                    output.push(Event::Conflict {
                        flow: flow.clone(),
                        stream,
                        generation,
                    });
                }
            }
            TcpEvent::Gap { .. } => output.push(Event::Gap {
                flow: flow.clone(),
                stream,
                generation,
            }),
            TcpEvent::Closed { reset, .. } => {
                self.closed.insert(flow.clone());
                if *reset {
                    self.closed.insert(flow.reverse());
                }
                output.push(Event::Closed {
                    flow: flow.clone(),
                    stream,
                    generation,
                    reset: *reset,
                });
            }
            TcpEvent::Evicted { .. } => {
                self.forget_spans(flow);
                output.push(Event::Evicted {
                    flow: flow.clone(),
                    stream,
                    generation,
                });
            }
        }
        Ok(())
    }
    fn subtract(
        &mut self,
        flow: &ScopedFlowKey,
        sequence: u32,
        length: u32,
        number: Option<u64>,
    ) -> Result<(), Error> {
        let Some(previous) = self.spans.get(flow) else {
            return Ok(());
        };
        if length == 0 {
            return Ok(());
        }
        let start = previous.offset(sequence);
        let end = start + i128::from(length);
        let affected: Vec<_> = previous
            .overlapping(start, end)
            .filter(|(_, span)| number.is_none_or(|number| span.number == number))
            .map(|(&offset, span)| (offset, span.clone()))
            .collect();
        let mut remaining = Vec::new();
        for (offset, span) in &affected {
            let span_end = *offset + i128::from(span.length);
            if *offset < start {
                remaining.push((
                    *offset,
                    Span {
                        length: (start - *offset) as u32,
                        ..span.clone()
                    },
                ));
            }
            if span_end > end {
                remaining.push((
                    end,
                    Span {
                        sequence: span.sequence.wrapping_add((end - *offset) as u32),
                        length: (span_end - end) as u32,
                        ..span.clone()
                    },
                ));
            }
        }
        let count = self.span_count - affected.len() + remaining.len();
        self.limits.check_source_spans(count)?;
        self.span_count = count;
        let previous = self.spans.get_mut(flow).expect("spans were checked above");
        for (offset, _) in affected {
            previous.ranges.remove(&offset);
        }
        previous.ranges.extend(remaining);
        if previous.ranges.is_empty() {
            self.spans.remove(flow);
        }
        Ok(())
    }
}
