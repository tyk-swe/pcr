// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Constraint, FrameRecord, ScopedFlowKey, TcpEventRecord,
    provenance::SourceSet,
    reassembly::tcp::{Event as TcpEvent, EvictionReason},
    scope::Definition,
};
use crate::error::{Classification, Classified, Kind};
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
pub(crate) struct TcpStreamFilter {
    ports: Vec<u16>,
    limits: Limits,
    streams: HashSet<u64>,
    scopes: BTreeMap<u32, Definition>,
    span_counts: HashMap<ScopedFlowKey, usize>,
    source_span_count: usize,
}

impl TcpStreamFilter {
    pub(crate) fn new(ports: Vec<u16>, limits: Limits) -> Self {
        Self {
            ports,
            limits,
            streams: HashSet::new(),
            scopes: BTreeMap::new(),
            span_counts: HashMap::new(),
            source_span_count: 0,
        }
    }

    pub(crate) fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.scopes.values()
    }

    pub(crate) fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        if let Some(view) = record.tcp
            && let Some(conversation) = view.conversation
            && self.matches(conversation.flow)
        {
            self.track_stream(conversation.index)?;
            if let Some(scope) = record.scope_definition(conversation.flow.scope) {
                self.scopes
                    .entry(scope.id.get())
                    .or_insert_with(|| scope.clone());
            }
        }
        let output = self.project_many(record.tcp_events, record.number)?;
        if let Some(view) = record.tcp
            && let Some(conversation) = view.conversation
            && self.matches(conversation.flow)
        {
            self.track_source_spans(conversation.flow, view.pending_source_spans)?;
        }
        Ok(output)
    }

    pub(crate) fn trailing(
        &mut self,
        events: &[TcpEventRecord],
        number: u64,
    ) -> Result<Vec<Event>, Error> {
        self.project_many(events, number)
    }

    fn project_many(
        &mut self,
        events: &[TcpEventRecord],
        number: u64,
    ) -> Result<Vec<Event>, Error> {
        let mut output = Vec::new();
        for event in events {
            self.project(event, number, &mut output)?;
        }
        Ok(output)
    }

    fn project(
        &mut self,
        record: &TcpEventRecord,
        number: u64,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let flow = match &record.event {
            TcpEvent::Data { flow, .. }
            | TcpEvent::Retransmission { flow, .. }
            | TcpEvent::Gap { flow, .. }
            | TcpEvent::Closed { flow, .. }
            | TcpEvent::Evicted { flow, .. } => flow,
        };
        if !self.matches(flow) {
            return Ok(());
        }
        if matches!(
            record.event,
            TcpEvent::Closed { .. } | TcpEvent::Evicted { .. }
        ) {
            self.forget_source_spans(flow);
        }
        self.track_stream(record.stream)?;
        match &record.event {
            TcpEvent::Data { bytes, sources, .. } => {
                for (bytes, set) in sources.slices(bytes) {
                    let Some(sources) = set else {
                        return Err(Error::Sources { number });
                    };
                    output.push(Event::Data(Delivery {
                        flow: flow.clone(),
                        stream: record.stream,
                        generation: record.generation,
                        bytes,
                        sources,
                    }));
                }
            }
            TcpEvent::Retransmission { conflicting, .. } if *conflicting => {
                output.push(Event::Conflict {
                    flow: flow.clone(),
                    stream: record.stream,
                    generation: record.generation,
                });
            }
            TcpEvent::Gap { .. } => output.push(Event::Gap {
                flow: flow.clone(),
                stream: record.stream,
                generation: record.generation,
            }),
            TcpEvent::Closed { reset, .. } => output.push(Event::Closed {
                flow: flow.clone(),
                stream: record.stream,
                generation: record.generation,
                reset: *reset,
            }),
            TcpEvent::Evicted { reason, .. } if *reason != EvictionReason::Reset => {
                output.push(Event::Evicted {
                    flow: flow.clone(),
                    stream: record.stream,
                    generation: record.generation,
                });
            }
            TcpEvent::Retransmission { .. } | TcpEvent::Evicted { .. } => {}
        }
        Ok(())
    }

    fn matches(&self, flow: &ScopedFlowKey) -> bool {
        self.ports.contains(&flow.flow.source_port)
            || self.ports.contains(&flow.flow.destination_port)
    }

    fn track_source_spans(&mut self, flow: &ScopedFlowKey, spans: usize) -> Result<(), Error> {
        let previous = self.span_counts.remove(flow).unwrap_or(0);
        self.source_span_count = self.source_span_count.saturating_sub(previous);
        if spans != 0 {
            self.span_counts.insert(flow.clone(), spans);
            self.source_span_count = self.source_span_count.saturating_add(spans);
        }
        self.limits.check_source_spans(self.source_span_count)
    }

    fn forget_source_spans(&mut self, flow: &ScopedFlowKey) {
        if let Some(spans) = self.span_counts.remove(flow) {
            self.source_span_count = self.source_span_count.saturating_sub(spans);
        }
    }

    fn track_stream(&mut self, stream: u64) -> Result<(), Error> {
        if !self.streams.contains(&stream) {
            self.limits.check_streams(self.streams.len())?;
            self.streams.insert(stream);
        }
        Ok(())
    }
}
