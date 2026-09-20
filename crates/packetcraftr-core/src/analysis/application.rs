// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounds and sourced TCP deliveries for offline application collectors.

use super::{
    FrameRecord,
    provenance::SourceSet,
    reassembly::tcp::{Event as TcpEvent, ScopedFlowKey},
    scope::Definition,
};
use crate::{
    error::{Classification, Classified, Kind},
    protocol::transport::Tcp,
};
use bytes::Bytes;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Distinct application messages the collector may count across all
    /// streams over the whole run: HTTP counts a message when its first byte
    /// arrives, DNS when it emits a framed message.
    pub max_messages: usize,
    /// Distinct transport streams the collector may track at once. HTTP
    /// counts TCP conversations; DNS counts each UDP flow and TCP stream.
    pub max_streams: usize,
    /// Bytes held at once across all in-flight message parses: partial heads
    /// and body-decoder buffers for HTTP, TCP length prefixes and partial
    /// bodies for DNS.
    pub max_buffer_bytes: usize,
    /// Cumulative byte charge for retained and emitted evidence over the
    /// run: parsed heads and flushed message state for HTTP, emitted wire
    /// bytes plus pending transaction keys for DNS. Charges include a
    /// conservative multiplier for decoded-object expansion, so this bounds
    /// result growth rather than live buffers or serialized output.
    pub max_retained_bytes: usize,
    /// TCP sequence spans retained to attribute reassembled deliveries to
    /// physical source frames. HTTP additionally bounds the distinct source
    /// frames one message may carry by this limit.
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
    #[error("application event output failed: {0}")]
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
}
impl Limits {
    pub(crate) fn validate(&self) -> Result<(), Error> {
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
            if value == 0 || value > maximum {
                return Err(Error::Limit {
                    field,
                    limit: maximum,
                });
            }
        }
        Ok(())
    }
}

/// The distinct service ports one application collector may follow.
pub(crate) const MAX_SERVICE_PORTS: usize = 256;

/// Collects, sorts, and deduplicates configured service ports, rejecting an
/// empty normalized list, port zero, and more than [`MAX_SERVICE_PORTS`]
/// distinct ports. `field` names the caller's protocol-specific limit in the
/// error; the bound applies to distinct ports, not input elements.
pub(crate) fn normalize_ports(
    ports: impl IntoIterator<Item = u16>,
    field: &'static str,
) -> Result<Vec<u16>, Error> {
    let mut ports: Vec<u16> = ports.into_iter().collect();
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() || ports.len() > MAX_SERVICE_PORTS || ports.contains(&0) {
        return Err(Error::Limit {
            field,
            limit: MAX_SERVICE_PORTS,
        });
    }
    Ok(ports)
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
        let mut incoming = None;
        let mut insert_after = None;
        if let Some(view) = record.tcp
            && let Some(conversation) = view.conversation
        {
            let flow = conversation.flow;
            if self.ports.contains(&flow.flow.source_port)
                || self.ports.contains(&flow.flow.destination_port)
            {
                if !self.generations.contains_key(&conversation.index)
                    && self.generations.len() >= self.limits.max_streams
                {
                    return Err(Error::Limit {
                        field: "max_streams",
                        limit: self.limits.max_streams,
                    });
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
                if !view.payload.is_empty() {
                    let sources = record
                        .tcp_sources()
                        .ok_or(Error::Sources {
                            number: record.number,
                        })?
                        .clone();
                    incoming = Some((
                        flow.clone(),
                        Span {
                            sequence: view
                                .header
                                .sequence
                                .wrapping_add(u32::from(view.header.flags & Tcp::SYN != 0)),
                            length: u32::try_from(view.payload.len()).map_err(|_| {
                                Error::Sources {
                                    number: record.number,
                                }
                            })?,
                            number: record.number,
                            sources,
                        },
                    ));
                    insert_after = last_stream_eviction;
                }
            }
        }
        if insert_after.is_none()
            && let Some((flow, span)) = incoming.take()
        {
            self.insert(flow, span)?;
        }
        for (index, event) in record.tcp_events.iter().enumerate() {
            self.event(event, record.number, &mut output)?;
            if insert_after == Some(index)
                && let Some((flow, span)) = incoming.take()
            {
                self.insert(flow, span)?;
            }
        }
        Ok(output)
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
            if let Some(spans) = self.spans.remove(&flow) {
                self.span_count -= spans.len();
            }
            self.closed.remove(&flow);
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
        if self.span_count.saturating_add(pieces.len()) > self.limits.max_source_spans {
            return Err(Error::Limit {
                field: "max_source_spans",
                limit: self.limits.max_source_spans,
            });
        }
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
                if let Some(spans) = self.spans.remove(flow) {
                    self.span_count -= spans.len();
                }
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
        if self.span_count.saturating_add(remaining.len()) > self.limits.max_source_spans {
            return Err(Error::Limit {
                field: "max_source_spans",
                limit: self.limits.max_source_spans,
            });
        }
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
    let offset = i64::from(other.wrapping_sub(base) as i32);
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
