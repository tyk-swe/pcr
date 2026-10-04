// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Constraint, FrameRecord,
    provenance::SourceSet,
    reassembly::tcp::{Event as TcpEvent, ScopedFlowKey},
    scope::Definition,
    serial::serial_offset,
};
use crate::{
    error::{Classification, Classified, Kind},
    protocol::transport::Tcp,
};
use bytes::Bytes;
use std::collections::{HashMap, HashSet};

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
    #[error("application event output failed")]
    Output(#[source] crate::error::BoundaryError),
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Analysis(source) => source.classification(),
            Self::Provenance(source) => source.classification(),
            Self::Output(source) => source.classification(),
            Self::Limit { .. } => Classification::new(
                "policy.application_limit",
                Kind::Policy,
                Some("raise a finite application-analysis limit or narrow the capture"),
            ),
            Self::Sources { .. } => Classification::new(
                "internal.application_sources",
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
    pub(crate) const fn decoded_charge(bytes: usize) -> usize {
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

    pub(crate) fn check_retained(&self, total: usize) -> Result<(), Error> {
        refuse_if(
            total > self.max_retained_bytes,
            "max_retained_bytes",
            self.max_retained_bytes,
        )
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
    let mut bounded = Vec::new();
    for port in ports {
        if bounded.len() == MAX_SERVICE_PORTS {
            return Err(super::Error::InvalidLimit {
                field,
                value: MAX_SERVICE_PORTS as u64 + 1,
                reason: Constraint::AtMost {
                    maximum: MAX_SERVICE_PORTS as u64,
                },
            }
            .into());
        }
        bounded.push(port);
    }
    let mut ports = bounded;
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
    },
    Conflict {
        flow: ScopedFlowKey,
        stream: u64,
    },
    Closed {
        flow: ScopedFlowKey,
        stream: u64,
        reset: bool,
    },
    Evicted {
        flow: ScopedFlowKey,
        stream: u64,
    },
}
#[derive(Clone)]
struct Span {
    sequence: u32,
    length: u32,
    number: u64,
    sources: SourceSet,
}
/// A payload span awaiting insertion; `after` is the index of the frame's
/// reassembly event it must follow, or `None` to precede them all.
struct Incoming {
    flow: ScopedFlowKey,
    span: Span,
    after: Option<usize>,
}

pub(crate) struct TcpSources {
    ports: Vec<u16>,
    limits: Limits,
    spans: HashMap<ScopedFlowKey, Vec<Span>>,
    span_count: usize,
    streams: HashMap<ScopedFlowKey, u64>,
    generations: HashMap<u64, u64>,
    syns: HashMap<ScopedFlowKey, u32>,
    closed: HashSet<ScopedFlowKey>,
    pub(crate) scopes: std::collections::BTreeMap<u32, Definition>,
}
impl TcpSources {
    pub(crate) fn new(ports: Vec<u16>, limits: Limits) -> Self {
        Self {
            ports,
            limits,
            spans: HashMap::new(),
            span_count: 0,
            streams: HashMap::new(),
            generations: HashMap::new(),
            syns: HashMap::new(),
            closed: HashSet::new(),
            scopes: Default::default(),
        }
    }
    pub(crate) fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        let mut output = Vec::new();
        let mut incoming = self.admit(record, &mut output)?;
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
                _ => self.event(event, record.number, &mut output)?,
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
        self.streams.insert(flow.clone(), conversation.index);
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
            self.event(event, number, &mut output)?;
        }
        Ok(output)
    }
    fn reset_stream(&mut self, stream: u64) {
        *self.generations.entry(stream).or_insert(0) += 1;
        let flows: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, id)| **id == stream)
            .map(|(flow, _)| flow.clone())
            .collect();
        for flow in flows {
            self.forget_spans(&flow);
            self.closed.remove(&flow);
        }
    }
    fn forget_spans(&mut self, flow: &ScopedFlowKey) {
        if let Some(spans) = self.spans.remove(flow) {
            self.span_count -= spans.len();
        }
    }
    fn insert(&mut self, flow: ScopedFlowKey, span: Span) -> Result<(), Error> {
        let mut pieces = vec![span];
        if let Some(previous) = self.spans.get(&flow) {
            for old in previous {
                pieces = pieces
                    .into_iter()
                    .flat_map(|piece| subtract(piece, old.sequence, old.length))
                    .collect();
            }
        }
        self.limits
            .check_source_spans(self.span_count.saturating_add(pieces.len()))?;
        self.span_count += pieces.len();
        self.spans.entry(flow).or_default().extend(pieces);
        Ok(())
    }
    fn event(
        &mut self,
        event: &TcpEvent,
        number: u64,
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
        match event {
            TcpEvent::Data {
                sequence, bytes, ..
            } => {
                let length = u32::try_from(bytes.len()).map_err(|_| Error::Sources { number })?;
                let mut parts = Vec::new();
                for span in self.spans.get(flow).into_iter().flatten() {
                    if let Some((lo, hi)) =
                        intersection(*sequence, length, span.sequence, span.length)
                    {
                        parts.push((lo, hi, span.sources.clone()));
                    }
                }
                parts.sort_by_key(|(lo, _, _)| *lo);
                let mut consumed = 0usize;
                for (lo, hi, sources) in parts {
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
                    });
                }
            }
            TcpEvent::Gap { .. } => output.push(Event::Gap {
                flow: flow.clone(),
                stream,
            }),
            TcpEvent::Closed { reset, .. } => {
                self.closed.insert(flow.clone());
                if *reset {
                    self.closed.insert(flow.reverse());
                }
                output.push(Event::Closed {
                    flow: flow.clone(),
                    stream,
                    reset: *reset,
                });
            }
            TcpEvent::Evicted { .. } => {
                self.forget_spans(flow);
                output.push(Event::Evicted {
                    flow: flow.clone(),
                    stream,
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
        let Some(previous) = self.spans.remove(flow) else {
            return Ok(());
        };
        self.span_count -= previous.len();
        let mut remaining = Vec::new();
        for span in previous {
            if number.is_none_or(|number| span.number == number) {
                remaining.extend(subtract(span, sequence, length));
            } else {
                remaining.push(span);
            }
        }
        self.limits
            .check_source_spans(self.span_count.saturating_add(remaining.len()))?;
        self.span_count += remaining.len();
        if !remaining.is_empty() {
            self.spans.insert(flow.clone(), remaining);
        }
        Ok(())
    }
}
// TCP windows are smaller than the serial half-space; signed wrapping distance
// therefore orders any retained span relative to the delivered range.
fn intersection(base: u32, length: u32, other: u32, other_length: u32) -> Option<(usize, usize)> {
    let offset = serial_offset(other, base);
    let lo = offset.max(0);
    let hi = (offset + i64::from(other_length)).min(i64::from(length));
    (lo < hi).then_some((lo as usize, hi as usize))
}
fn subtract(span: Span, sequence: u32, length: u32) -> Vec<Span> {
    let Some((lo, hi)) = intersection(span.sequence, span.length, sequence, length) else {
        return vec![span];
    };
    let mut output = Vec::new();
    if lo > 0 {
        output.push(Span {
            length: lo as u32,
            ..span.clone()
        });
    }
    if hi < span.length as usize {
        output.push(Span {
            sequence: span.sequence.wrapping_add(hi as u32),
            length: span.length - hi as u32,
            ..span
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_port_iterator_is_bounded_before_collection() {
        let mut consumed = 0;
        let ports = std::iter::repeat(53).inspect(|_| consumed += 1);
        assert!(normalize_ports(ports, "dns_ports").is_err());
        assert_eq!(consumed, MAX_SERVICE_PORTS + 1);
        assert_eq!(
            normalize_ports([53, 53, 80], "dns_ports").unwrap(),
            [53, 80]
        );
    }

    const LIMITS: Limits = Limits {
        max_messages: 2,
        max_streams: 3,
        max_buffer_bytes: 5,
        max_retained_bytes: 7,
        max_source_spans: 11,
    };

    fn assert_limit(result: Result<(), Error>, field: &str, limit: usize) {
        match result {
            Err(Error::Limit {
                field: actual,
                limit: actual_limit,
            }) => assert_eq!((actual, actual_limit), (field, limit)),
            other => panic!("expected a {field} limit refusal, got {other:?}"),
        }
    }

    #[test]
    fn streams_and_messages_are_refused_once_the_limit_is_filled() {
        assert!(LIMITS.check_streams(2).is_ok());
        assert_limit(LIMITS.check_streams(3), "max_streams", 3);
        assert!(LIMITS.check_messages(1).is_ok());
        assert_limit(LIMITS.check_messages(2), "max_messages", 2);
        assert_limit(LIMITS.check_messages(usize::MAX), "max_messages", 2);
    }

    #[test]
    fn buffer_spans_and_retained_are_refused_only_above_the_limit() {
        assert!(LIMITS.check_buffer(5).is_ok());
        assert_limit(LIMITS.check_buffer(6), "max_buffer_bytes", 5);
        assert!(LIMITS.check_source_spans(11).is_ok());
        assert_limit(LIMITS.check_source_spans(12), "max_source_spans", 11);
        assert!(LIMITS.check_retained(7).is_ok());
        assert_limit(LIMITS.check_retained(8), "max_retained_bytes", 7);
        assert_limit(LIMITS.check_retained(usize::MAX), "max_retained_bytes", 7);
    }
}
