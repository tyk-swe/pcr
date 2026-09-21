// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline DNS framing and transaction evidence over scoped UDP and TCP flows.
//! Feed unfiltered records with TCP events and physical-source tracking enabled.
//! A missing response means only that no matching response was captured.

mod transactions;

use super::{
    FrameRecord, Summary as RunSummary,
    application::{self, Error, Limits, TcpSources},
    provenance::SourceSet,
    reassembly::tcp::ScopedFlowKey,
    scope::Definition,
};
use crate::{
    field::WireValue,
    protocol::{
        application::dns::{DecodeError, DecodeLimits, Dns},
        transport::Udp,
    },
};
use bytes::Bytes;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
pub use transactions::{Latency, Transaction, TransactionStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
}
/// The terminal state of a framed message on a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The declared wire body was fully captured.
    Complete,
    /// The message violated wire rules or length limits.
    Malformed,
    /// The stream ended before the declared wire body arrived.
    Incomplete,
    /// A sequence gap in the stream made the message unrecoverable.
    Gap,
    /// The same stream position carried conflicting bytes.
    Conflict,
    Reset,
    Evicted,
}
/// One framed DNS message on a UDP flow or TCP stream.
#[derive(Clone, Debug)]
pub struct Message {
    pub index: u64,
    pub transport: Transport,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub status: Status,
    /// Complete DNS wire or the captured part, excluding the TCP length prefix.
    pub wire: Bytes,
    pub declared_length: Option<u16>,
    pub framing_bytes: Bytes,
    pub dns: Option<Dns>,
    pub error: Option<DecodeError>,
    pub sources: SourceSet,
}
/// What the collector reports for each processed record.
#[derive(Clone, Debug)]
pub enum Event {
    /// A stream-level condition that invalidated pending messages.
    Issue(StreamIssue),
    /// A framed message reached a terminal state.
    Message(Box<Message>),
    /// A query/response pair settled into a final status.
    Transaction(Transaction),
}
/// A stream-level condition attributed to one direction of a flow.
#[derive(Clone, Debug, Serialize)]
pub struct StreamIssue {
    pub number: u64,
    pub flow: ScopedFlowKey,
    pub stream: u64,
    pub status: Status,
}
/// Cumulative counts over every record the collector has processed.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Summary {
    pub messages: u64,
    pub complete_messages: u64,
    pub transactions: u64,
    pub matched_transactions: u64,
    pub unanswered_transactions: u64,
    pub orphan_responses: u64,
    pub duplicate_responses: u64,
}

struct Direction {
    stream: u64,
    generation: u64,
    prefix: Vec<u8>,
    body: Vec<u8>,
    sources: Option<SourceSet>,
    disabled: bool,
}
impl Direction {
    fn new(stream: u64, generation: u64) -> Self {
        Self {
            stream,
            generation,
            prefix: Vec::new(),
            body: Vec::new(),
            sources: None,
            disabled: false,
        }
    }
    fn length(&self) -> Option<u16> {
        (self.prefix.len() == 2).then(|| u16::from_be_bytes([self.prefix[0], self.prefix[1]]))
    }
    fn used(&self) -> usize {
        self.prefix.len() + self.body.len()
    }
}
/// Collects DNS messages and transactions from reassembled flow deliveries.
///
/// Feed it unfiltered records with TCP events and physical-source tracking
/// enabled; it owns the wire framing, decode attempts, and query/response
/// correlation for every configured port.
pub struct Collector {
    limits: Limits,
    ports: Vec<u16>,
    seen_streams: BTreeSet<(Transport, u64)>,
    tcp: TcpSources,
    directions: BTreeMap<ScopedFlowKey, Direction>,
    scopes: BTreeMap<u32, Definition>,
    buffered: usize,
    emitted_bytes: usize,
    transactions: transactions::Tracker,
    summary: Summary,
}
impl Collector {
    /// Ports are explicit and bounded; use `[53]` for standard DNS.
    pub fn new(limits: Limits, ports: impl IntoIterator<Item = u16>) -> Result<Self, Error> {
        limits.validate()?;
        let ports = application::normalize_ports(ports, "dns_ports")?;
        Ok(Self {
            limits,
            tcp: TcpSources::new(ports.clone(), limits),
            ports,
            seen_streams: BTreeSet::new(),
            directions: BTreeMap::new(),
            scopes: BTreeMap::new(),
            buffered: 0,
            emitted_bytes: 0,
            transactions: transactions::Tracker::new(limits),
            summary: Summary::default(),
        })
    }
    fn register_stream(&mut self, transport: Transport, stream: u64) -> Result<(), Error> {
        if !self.seen_streams.contains(&(transport, stream))
            && self.seen_streams.len() >= self.limits.max_streams
        {
            return Err(Error::Limit {
                field: "max_streams",
                limit: self.limits.max_streams,
            });
        }
        self.seen_streams.insert((transport, stream));
        Ok(())
    }
    pub fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.scopes.values().chain(
            self.tcp
                .scopes
                .values()
                .filter(|scope| !self.scopes.contains_key(&scope.id.get())),
        )
    }
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        let mut events = Vec::new();
        if let Some(view) = record.udp
            && let Some(conversation) = view.conversation
        {
            let flow = conversation.flow;
            if self.ports.contains(&flow.flow.source_port)
                || self.ports.contains(&flow.flow.destination_port)
            {
                self.register_stream(Transport::Udp, conversation.index)?;
                if let Some(scope) = record.scope_definition(flow.scope) {
                    self.scopes
                        .entry(scope.id.get())
                        .or_insert_with(|| scope.clone());
                }
                let header = view
                    .decoded
                    .packet
                    .layer(view.layer)
                    .and_then(|layer| layer.as_any().downcast_ref::<Udp>())
                    .ok_or(Error::Sources {
                        number: record.number,
                    })?;
                let start = view
                    .decoded
                    .layout
                    .layer(view.layer)
                    .ok_or(Error::Sources {
                        number: record.number,
                    })?
                    .range
                    .end;
                let WireValue::Exact(length) = header.length else {
                    return Err(Error::Sources {
                        number: record.number,
                    });
                };
                let expected = usize::from(length).saturating_sub(8);
                let end = start
                    .saturating_add(expected)
                    .min(view.decoded.original.len());
                let wire = view.decoded.original.slice(start.min(end)..end);
                let sources = record
                    .udp_sources()
                    .ok_or(Error::Sources {
                        number: record.number,
                    })?
                    .clone();
                self.emit(
                    Message {
                        index: 0,
                        transport: Transport::Udp,
                        stream: conversation.index,
                        generation: 0,
                        flow: flow.clone(),
                        status: if wire.len() == expected {
                            Status::Complete
                        } else {
                            Status::Incomplete
                        },
                        wire,
                        declared_length: Some(length.saturating_sub(8)),
                        framing_bytes: Bytes::new(),
                        dns: None,
                        error: None,
                        sources,
                    },
                    &mut events,
                )?;
            }
        }
        if let Some(conversation) = record.tcp.and_then(|view| view.conversation)
            && (self.ports.contains(&conversation.flow.flow.source_port)
                || self
                    .ports
                    .contains(&conversation.flow.flow.destination_port))
        {
            self.register_stream(Transport::Tcp, conversation.index)?;
        }
        for event in self.tcp.observe(record)? {
            self.tcp_event(event, record.number, &mut events)?;
        }
        Ok(events)
    }
    pub fn finish(mut self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
        let mut events = Vec::new();
        for event in self
            .tcp
            .trailing(&run.trailing_tcp_events, run.frames_read)?
        {
            if let application::Event::Evicted { flow, stream } = event {
                self.stop(flow, stream, Status::Incomplete, &mut events)?;
            } else {
                self.tcp_event(event, run.frames_read, &mut events)?;
            }
        }
        for (flow, mut direction) in std::mem::take(&mut self.directions) {
            self.flush(&flow, &mut direction, Status::Incomplete, &mut events)?;
        }
        for transaction in self.transactions.finish() {
            self.transaction(transaction, &mut events);
        }
        Ok((events, self.summary))
    }
    fn tcp_event(
        &mut self,
        event: application::Event,
        number: u64,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let issue = match &event {
            application::Event::Gap { flow, stream } => Some((flow, stream, Status::Gap)),
            application::Event::Conflict { flow, stream } => Some((flow, stream, Status::Conflict)),
            application::Event::Evicted { flow, stream } => Some((flow, stream, Status::Evicted)),
            application::Event::Closed {
                flow,
                stream,
                reset: true,
            } => Some((flow, stream, Status::Reset)),
            _ => None,
        };
        if let Some((flow, stream, status)) = issue {
            events.push(Event::Issue(StreamIssue {
                number,
                flow: flow.clone(),
                stream: *stream,
                status,
            }));
        }
        match event {
            application::Event::Data(data) => {
                let mut direction = self
                    .directions
                    .remove(&data.flow)
                    .unwrap_or_else(|| Direction::new(data.stream, data.generation));
                if direction.generation != data.generation {
                    self.flush(&data.flow, &mut direction, Status::Evicted, events)?;
                    direction = Direction::new(data.stream, data.generation);
                }
                let mut input = data.bytes.as_ref();
                while !direction.disabled && !input.is_empty() {
                    let needed = direction
                        .length()
                        .map_or(2 - direction.prefix.len(), |len| {
                            usize::from(len) - direction.body.len()
                        });
                    let take = needed.min(input.len());
                    if self.buffered.saturating_add(take) > self.limits.max_buffer_bytes {
                        return Err(Error::Limit {
                            field: "max_buffer_bytes",
                            limit: self.limits.max_buffer_bytes,
                        });
                    }
                    direction.sources = Some(match direction.sources.take() {
                        Some(old) => old.union(&data.sources)?,
                        None => data.sources.clone(),
                    });
                    if direction.prefix.len() < 2 {
                        direction.prefix.extend_from_slice(&input[..take]);
                    } else {
                        direction.body.extend_from_slice(&input[..take]);
                    }
                    self.buffered += take;
                    input = &input[take..];
                    if direction
                        .length()
                        .is_some_and(|len| direction.body.len() == usize::from(len))
                    {
                        self.flush(&data.flow, &mut direction, Status::Complete, events)?;
                    }
                }
                self.directions.insert(data.flow, direction);
            }
            application::Event::Gap { flow, stream } => {
                self.stop(flow, stream, Status::Gap, events)?;
            }
            application::Event::Conflict { flow, stream } => {
                self.stop(flow, stream, Status::Conflict, events)?;
            }
            application::Event::Evicted { flow, stream } => {
                self.stop(flow, stream, Status::Evicted, events)?;
            }
            application::Event::Closed {
                flow,
                stream,
                reset,
            } => {
                self.stop(
                    flow.clone(),
                    stream,
                    if reset {
                        Status::Reset
                    } else {
                        Status::Incomplete
                    },
                    events,
                )?;
                if reset {
                    self.stop(flow.reverse(), stream, Status::Reset, events)?;
                }
            }
        }
        Ok(())
    }
    fn stop(
        &mut self,
        flow: ScopedFlowKey,
        _stream: u64,
        status: Status,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if let Some(mut direction) = self.directions.remove(&flow) {
            self.flush(&flow, &mut direction, status, events)?;
            direction.disabled = true;
            self.directions.insert(flow, direction);
        }
        Ok(())
    }
    fn flush(
        &mut self,
        flow: &ScopedFlowKey,
        direction: &mut Direction,
        status: Status,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let Some(sources) = direction.sources.take() else {
            return Ok(());
        };
        let declared_length = direction.length();
        self.buffered -= direction.used();
        let framing_bytes = Bytes::from(std::mem::take(&mut direction.prefix));
        let wire = Bytes::from(std::mem::take(&mut direction.body));
        self.emit(
            Message {
                index: 0,
                transport: Transport::Tcp,
                stream: direction.stream,
                generation: direction.generation,
                flow: flow.clone(),
                status,
                wire,
                declared_length,
                framing_bytes,
                dns: None,
                error: None,
                sources,
            },
            events,
        )
    }
    fn emit(&mut self, mut message: Message, events: &mut Vec<Event>) -> Result<(), Error> {
        if self.summary.messages as usize >= self.limits.max_messages {
            return Err(Error::Limit {
                field: "max_messages",
                limit: self.limits.max_messages,
            });
        }
        // The decoder's bounded object expansion is conservatively charged along with wire.
        let charge = message.wire.len().saturating_mul(32).saturating_add(4096);
        self.emitted_bytes = self.emitted_bytes.saturating_add(charge);
        if self.emitted_bytes > self.limits.max_retained_bytes {
            return Err(Error::Limit {
                field: "max_retained_bytes",
                limit: self.limits.max_retained_bytes,
            });
        }
        self.summary.messages += 1;
        message.index = self.summary.messages;
        if message.status == Status::Complete {
            match Dns::from_wire_with_limits(message.wire.clone(), DecodeLimits::default()) {
                Ok(dns) => {
                    self.summary.complete_messages += 1;
                    message.dns = Some(dns);
                }
                Err(error) => {
                    message.error = Some(error);
                    message.status = Status::Malformed;
                }
            }
        }
        let transactions = self.transactions.observe(&message)?;
        events.push(Event::Message(Box::new(message)));
        for transaction in transactions {
            self.transaction(transaction, events);
        }
        Ok(())
    }
    fn transaction(&mut self, transaction: Transaction, events: &mut Vec<Event>) {
        self.summary.transactions += 1;
        match transaction.status {
            TransactionStatus::Matched => self.summary.matched_transactions += 1,
            TransactionStatus::Unanswered => self.summary.unanswered_transactions += 1,
            TransactionStatus::OrphanResponse => self.summary.orphan_responses += 1,
            TransactionStatus::DuplicateResponse => self.summary.duplicate_responses += 1,
        }
        events.push(Event::Transaction(transaction));
    }
}
