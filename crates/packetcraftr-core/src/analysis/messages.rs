// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, sourced message decoding over reassembled TCP. Selection is fixed
//! for a connection generation; malformed framing never initiates a byte scan.

use super::{
    FrameRecord, Summary as RunSummary,
    application::{self, Error, Limits, TcpSources},
    provenance::{Accumulator, SourceSet},
    reassembly::tcp::ScopedFlowKey,
    scope::Definition,
    session::{self, CollectorNeeds},
};
use crate::{
    codec::{DecodeContext, NetworkEnvelope},
    error::BoundaryError,
    packet::Packet,
    protocol::{BuiltinProtocol, framing::Framer},
    registry::{Discriminator, Registry},
};
use bytes::Bytes;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Incomplete,
    Malformed,
    Unsupported,
    Gap,
    Conflict,
    Reset,
    Evicted,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub index: u64,
    pub protocol: BuiltinProtocol,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub status: Status,
    pub wire: Bytes,
    pub packet: Option<Packet>,
    pub error: Option<String>,
    pub sources: SourceSet,
}
#[derive(Clone, Debug, Serialize)]
pub struct Issue {
    pub number: u64,
    pub flow: ScopedFlowKey,
    pub stream: u64,
    pub status: Status,
}
#[derive(Clone, Debug)]
pub enum Event {
    Message(Box<Message>),
    Issue(Issue),
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Summary {
    pub messages: u64,
    pub complete_messages: u64,
    pub incomplete_messages: u64,
    pub malformed_messages: u64,
    pub unsupported_messages: u64,
    pub by_protocol: BTreeMap<String, u64>,
}

struct Direction {
    stream: u64,
    generation: u64,
    protocol: BuiltinProtocol,
    buffer: Vec<u8>,
    offset: usize,
    framer: Framer,
    sources: Option<Accumulator>,
    disabled: bool,
}
impl Direction {
    fn new(stream: u64, generation: u64, protocol: BuiltinProtocol) -> Self {
        Self {
            stream,
            generation,
            protocol,
            buffer: Vec::new(),
            offset: 0,
            framer: Framer::new(protocol.framing(), protocol.as_str()),
            sources: None,
            disabled: false,
        }
    }
}

#[derive(Clone, Copy)]
struct Connection {
    generation: u64,
    protocol: Option<BuiltinProtocol>,
    server: Option<(std::net::IpAddr, u16)>,
    mqtt_level: Option<u8>,
    unsupported_amqp: bool,
}

pub struct Collector {
    limits: Limits,
    registry: Arc<Registry>,
    selected: BTreeSet<BuiltinProtocol>,
    tcp: TcpSources,
    connections: BTreeMap<u64, Connection>,
    directions: BTreeMap<ScopedFlowKey, Direction>,
    stopped: BTreeMap<ScopedFlowKey, (u64, u64)>,
    buffered: usize,
    buffer_capacity: usize,
    retained: usize,
    summary: Summary,
}
impl Collector {
    pub fn new(
        limits: Limits,
        registry: Arc<Registry>,
        protocols: impl IntoIterator<Item = BuiltinProtocol>,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let selected: BTreeSet<_> = protocols.into_iter().collect();
        if selected.is_empty() {
            return Err(Error::Protocol {
                protocol: "empty selection".into(),
            });
        }
        if let Some(protocol) = selected.iter().find(|p| !p.stream_decode()) {
            return Err(Error::Protocol {
                protocol: protocol.as_str().into(),
            });
        }
        let mut ports = Vec::new();
        for p in &selected {
            for (parent, d) in registry.parent_bindings(p.as_str()) {
                if parent.as_str() == "tcp"
                    && d.0 > 0
                    && d.0 <= 65535
                    && registry.child_for("tcp", d) == Some(crate::layer::Id::new(p.as_str()))
                {
                    ports.push(d.0 as u16);
                }
            }
        }
        ports.sort_unstable();
        ports.dedup();
        Ok(Self {
            limits,
            registry,
            selected,
            tcp: TcpSources::new(ports, limits),
            connections: BTreeMap::new(),
            directions: BTreeMap::new(),
            stopped: BTreeMap::new(),
            buffered: 0,
            buffer_capacity: 0,
            retained: 0,
            summary: Summary::default(),
        })
    }
    pub fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.tcp.scopes.values()
    }
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        let mut events = Vec::new();
        let deliveries = self.tcp.observe(record)?;
        if let Some(tcp) = record.tcp
            && tcp.header.flags & crate::protocol::transport::Tcp::SYN != 0
            && let Some(conversation) = tcp.conversation
            && let Some(generation) = self.tcp.generation(conversation.index)
            && self
                .connections
                .get(&conversation.index)
                .is_none_or(|connection| connection.generation != generation)
        {
            let flow = &conversation.flow.flow;
            let server = if tcp.header.flags & crate::protocol::transport::Tcp::ACK == 0 {
                (flow.destination, flow.destination_port)
            } else {
                (flow.source, flow.source_port)
            };
            self.connections.insert(
                conversation.index,
                Connection {
                    generation,
                    protocol: self.protocol_for_port(server.1),
                    server: Some(server),
                    mqtt_level: None,
                    unsupported_amqp: false,
                },
            );
        }
        for event in deliveries {
            self.event(event, record.number, &mut events)?;
        }
        Ok(events)
    }
    fn finalize(
        mut self,
        run: &RunSummary,
        mut check: impl FnMut() -> Result<(), Error>,
        mut emit: impl FnMut(Vec<Event>) -> Result<(), Error>,
    ) -> Result<Summary, Error> {
        for event in self
            .tcp
            .trailing(&run.trailing_tcp_events, run.frames_read)?
        {
            check()?;
            let mut out = Vec::new();
            if let application::Event::Evicted {
                flow,
                stream,
                generation,
            } = event
            {
                self.stop(&flow, stream, generation, Status::Incomplete, &mut out)?;
            } else {
                self.event(event, run.frames_read, &mut out)?;
            }
            emit(out)?;
        }
        for (flow, mut direction) in std::mem::take(&mut self.directions) {
            check()?;
            let mut out = Vec::new();
            self.flush(&flow, &mut direction, Status::Incomplete, None, &mut out)?;
            emit(out)?;
        }
        check()?;
        Ok(self.summary)
    }
    fn event(
        &mut self,
        event: application::Event,
        number: u64,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let (flow, stream, generation, status) = match event {
            application::Event::Data(data) => return self.data(data, out),
            application::Event::Gap {
                flow,
                stream,
                generation,
            } => (flow, stream, generation, Status::Gap),
            application::Event::Conflict {
                flow,
                stream,
                generation,
            } => (flow, stream, generation, Status::Conflict),
            application::Event::Evicted {
                flow,
                stream,
                generation,
            } => (flow, stream, generation, Status::Evicted),
            application::Event::Closed {
                flow,
                stream,
                generation,
                reset,
            } => (
                flow,
                stream,
                generation,
                if reset {
                    Status::Reset
                } else {
                    Status::Incomplete
                },
            ),
        };
        if status != Status::Incomplete {
            out.push(Event::Issue(Issue {
                number,
                flow: flow.clone(),
                stream,
                status,
            }));
        }
        self.stop(&flow, stream, generation, status, out)?;
        if status == Status::Reset {
            self.stop(&flow.reverse(), stream, generation, status, out)?;
        }
        Ok(())
    }
    fn select(&mut self, data: &application::Delivery) -> Option<BuiltinProtocol> {
        if let Some(connection) = self.connections.get(&data.stream)
            && connection.generation == data.generation
        {
            return connection.protocol;
        }
        let p = [data.flow.flow.destination_port, data.flow.flow.source_port]
            .into_iter()
            .find_map(|port| self.protocol_for_port(port));
        self.connections.insert(
            data.stream,
            Connection {
                generation: data.generation,
                protocol: p,
                server: None,
                mqtt_level: None,
                unsupported_amqp: false,
            },
        );
        p
    }
    fn protocol_for_port(&self, port: u16) -> Option<BuiltinProtocol> {
        self.registry
            .child_for("tcp", Discriminator(u64::from(port)))
            .and_then(BuiltinProtocol::from_id)
            .filter(|p| self.selected.contains(p))
    }
    fn data(&mut self, data: application::Delivery, out: &mut Vec<Event>) -> Result<(), Error> {
        if self.stopped.get(&data.flow) == Some(&(data.stream, data.generation)) {
            return Ok(());
        }
        self.stopped.remove(&data.flow);
        let Some(protocol) = self.select(&data) else {
            return Ok(());
        };
        let mut d = self
            .directions
            .remove(&data.flow)
            .unwrap_or_else(|| Direction::new(data.stream, data.generation, protocol));
        let result = (|| {
            if d.generation != data.generation {
                self.flush(&data.flow, &mut d, Status::Evicted, None, out)?;
                d = Direction::new(data.stream, data.generation, protocol);
            }
            if !d.disabled {
                self.limits
                    .check_buffer(self.buffered.saturating_add(data.bytes.len()))?;
                self.reserve_buffer(&mut d, data.bytes.len())?;
                if let Some(sources) = d.sources.as_mut() {
                    self.limits
                        .check_source_spans(sources.len_with(&data.sources)?)?;
                    sources.insert(&data.sources)?;
                } else {
                    self.limits.check_source_spans(data.sources.len())?;
                    d.sources = Some(Accumulator::new(&data.sources)?);
                }
                d.buffer.extend_from_slice(&data.bytes);
                self.buffered += data.bytes.len();
                while d.offset < d.buffer.len() && !d.disabled && !self.opaque(&d) {
                    // Stream-level SIP keepalives are not messages. A lone CR waits for
                    // the next delivery, so split CRLFs retain the same framing behavior.
                    if d.protocol == BuiltinProtocol::Sip
                        && d.buffer[d.offset..].starts_with(b"\r\n")
                    {
                        let next_offset = d.offset + 2;
                        let sources = if next_offset < d.buffer.len() {
                            Some(Accumulator::new(&data.sources)?)
                        } else {
                            None
                        };
                        d.offset = next_offset;
                        self.buffered -= 2;
                        d.framer = Framer::new(d.protocol.framing(), d.protocol.as_str());
                        d.sources = sources;
                        continue;
                    }
                    match d
                        .framer
                        .progress(&d.buffer[d.offset..], self.limits.max_buffer_bytes)
                    {
                        Ok(Some(len)) => {
                            if len == 0 {
                                d.framer = Framer::new(d.protocol.framing(), d.protocol.as_str());
                                return Err(Error::Limit {
                                    field: "zero_length_message",
                                    limit: 0,
                                });
                            }
                            let next_offset = d.offset + len;
                            let emission = (|| {
                                let remaining_sources = if next_offset < d.buffer.len() {
                                    Some(Accumulator::new(&data.sources)?)
                                } else {
                                    None
                                };
                                let wire = Bytes::copy_from_slice(&d.buffer[d.offset..next_offset]);
                                let sources = d
                                    .sources
                                    .as_ref()
                                    .expect("buffered message has sources")
                                    .snapshot()?;
                                let mut message = Message {
                                    index: 0,
                                    protocol: d.protocol,
                                    stream: d.stream,
                                    generation: d.generation,
                                    flow: data.flow.clone(),
                                    status: Status::Complete,
                                    wire,
                                    packet: None,
                                    error: None,
                                    sources,
                                };
                                self.decode(&mut message);
                                self.emit(message, out)?;
                                Ok::<_, Error>(remaining_sources)
                            })();
                            let remaining_sources = match emission {
                                Ok(sources) => sources,
                                Err(error) => {
                                    d.framer =
                                        Framer::new(d.protocol.framing(), d.protocol.as_str());
                                    return Err(error);
                                }
                            };
                            d.offset = next_offset;
                            self.buffered -= len;
                            d.framer = Framer::new(d.protocol.framing(), d.protocol.as_str());
                            d.sources = remaining_sources;
                        }
                        Ok(None) => break,
                        Err(crate::protocol::framing::Error::BufferLimit { limit }) => {
                            d.framer = Framer::new(d.protocol.framing(), d.protocol.as_str());
                            return Err(Error::Limit {
                                field: "max_buffer_bytes",
                                limit,
                            });
                        }
                        Err(crate::protocol::framing::Error::Codec(error)) => {
                            let status = if matches!(error, crate::codec::Error::Unsupported { .. })
                            {
                                Status::Unsupported
                            } else {
                                Status::Malformed
                            };
                            if let Err(error) =
                                self.flush(&data.flow, &mut d, status, Some(error.to_string()), out)
                            {
                                d.framer = Framer::new(d.protocol.framing(), d.protocol.as_str());
                                return Err(error);
                            }
                            d.disabled = true;
                        }
                    }
                }
                if d.offset == d.buffer.len() {
                    d.buffer.clear();
                    d.offset = 0;
                }
            }
            Ok(())
        })();
        self.directions.insert(data.flow, d);
        result
    }
    fn reserve_buffer(
        &mut self,
        direction: &mut Direction,
        additional: usize,
    ) -> Result<(), Error> {
        if direction.buffer.capacity() - direction.buffer.len() >= additional {
            return Ok(());
        }
        compact_buffer(direction);
        let needed = direction.buffer.len().saturating_add(additional);
        if needed <= direction.buffer.capacity() {
            return Ok(());
        }
        if self.buffer_capacity - direction.buffer.capacity() + needed
            > self.limits.max_buffer_bytes
        {
            for other in self.directions.values_mut() {
                let previous = other.buffer.capacity();
                compact_buffer(other);
                other.buffer.shrink_to_fit();
                self.buffer_capacity -= previous - other.buffer.capacity();
            }
        }
        let available =
            self.limits.max_buffer_bytes - (self.buffer_capacity - direction.buffer.capacity());
        self.limits.check_buffer(
            needed.saturating_add(self.buffer_capacity - direction.buffer.capacity()),
        )?;
        let target = needed.max(direction.buffer.capacity().saturating_mul(2).min(available));
        let previous = direction.buffer.capacity();
        direction
            .buffer
            .try_reserve_exact(target - direction.buffer.len())
            .map_err(|_| Error::Limit {
                field: "max_buffer_bytes",
                limit: self.limits.max_buffer_bytes,
            })?;
        self.buffer_capacity += direction.buffer.capacity() - previous;
        #[cfg(test)]
        BUFFER_STATS.with(|stats| {
            let (allocations, copied, peak) = stats.get();
            stats.set((allocations + 1, copied, peak.max(self.buffer_capacity)));
        });
        self.limits.check_buffer(self.buffer_capacity)
    }
    fn decode(&mut self, message: &mut Message) {
        if message.protocol == BuiltinProtocol::Amqp
            && message.wire.starts_with(b"AMQP")
            && message.wire.as_ref() != b"AMQP\0\0\x09\x01"
        {
            self.connections
                .get_mut(&message.stream)
                .expect("selected connection exists")
                .unsupported_amqp = true;
            message.status = Status::Unsupported;
            message.error =
                Some("only AMQP 0-9-1 is supported; connection bytes remain opaque".into());
            return;
        }
        if message.protocol == BuiltinProtocol::Mqtt {
            let connection = self
                .connections
                .get_mut(&message.stream)
                .expect("selected connection exists");
            if let Some(level) =
                crate::protocol::application::mqtt::connect_protocol_level(&message.wire)
                && (connection.mqtt_level.is_none() || level != 4)
            {
                connection.mqtt_level = Some(level);
            }
            if let Some(level) = connection.mqtt_level.filter(|level| *level != 4) {
                message.status = Status::Unsupported;
                message.error = Some(format!(
                    "MQTT protocol level {level} is unsupported; connection messages remain opaque"
                ));
                return;
            }
        }
        let codec = self
            .registry
            .codec(message.protocol.as_str())
            .expect("selected built-in codec");
        let context = DecodeContext {
            parent: Some(crate::protocol::BuiltinProtocol::Tcp.id()),
            registry: &self.registry,
            network: Some(NetworkEnvelope {
                source: message.flow.flow.source,
                destination: message.flow.flow.destination,
            }),
            hop_limit: None,
            discriminator: None,
        };
        match codec.decode(message.wire.clone(), &context) {
            Ok(decoded) if decoded.layer.protocol_id().as_str() == message.protocol.as_str() => {
                let mut layer = decoded.layer;
                if BuiltinProtocol::ModbusTcp.identifies(&*layer) {
                    let flow = &message.flow.flow;
                    let response = self.connections[&message.stream]
                        .server
                        .map(|server| server == (flow.source, flow.source_port))
                        .or_else(|| {
                            let source = self.protocol_for_port(flow.source_port)
                                == Some(BuiltinProtocol::ModbusTcp);
                            let destination = self.protocol_for_port(flow.destination_port)
                                == Some(BuiltinProtocol::ModbusTcp);
                            (source != destination).then_some(source)
                        });
                    if let Some(response) = response
                        && let Some(Err(error)) =
                            crate::protocol::application::modbus_tcp::ModbusTcp::interpret_layer(
                                &mut *layer,
                                response,
                            )
                    {
                        message.status = Status::Malformed;
                        message.error = Some(error.to_string());
                        return;
                    }
                }
                let mut p = Packet::default();
                p.push_boxed(layer);
                message.packet = Some(p);
            }
            Ok(_) => {
                message.status = Status::Unsupported;
                message.error = Some("message is outside the supported wire-format subset".into());
            }
            Err(e) => {
                message.status = Status::Malformed;
                message.error = Some(e.to_string());
            }
        }
    }
    fn emit(&mut self, mut message: Message, out: &mut Vec<Event>) -> Result<(), Error> {
        self.limits.check_messages(self.summary.messages as usize)?;
        let retained = self
            .retained
            .saturating_add(Limits::decoded_charge(message.wire.len()));
        self.limits.check_retained(retained)?;
        self.retained = retained;
        self.summary.messages += 1;
        message.index = self.summary.messages;
        *self
            .summary
            .by_protocol
            .entry(message.protocol.as_str().to_owned())
            .or_default() += 1;
        match message.status {
            Status::Complete => self.summary.complete_messages += 1,
            Status::Malformed => self.summary.malformed_messages += 1,
            Status::Unsupported => self.summary.unsupported_messages += 1,
            _ => self.summary.incomplete_messages += 1,
        }
        out.push(Event::Message(Box::new(message)));
        Ok(())
    }
    fn flush(
        &mut self,
        flow: &ScopedFlowKey,
        d: &mut Direction,
        mut status: Status,
        mut error: Option<String>,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if d.offset == d.buffer.len() {
            self.buffer_capacity -= d.buffer.capacity();
            d.buffer = Vec::new();
            d.offset = 0;
            return Ok(());
        }
        if status == Status::Incomplete && self.opaque(d) {
            status = Status::Unsupported;
            error = Some("AMQP connection uses an unsupported protocol version".into());
        }
        let wire = Bytes::copy_from_slice(&d.buffer[d.offset..]);
        let sources = d
            .sources
            .as_ref()
            .expect("buffered bytes have sources")
            .snapshot()?;
        self.emit(
            Message {
                index: 0,
                protocol: d.protocol,
                stream: d.stream,
                generation: d.generation,
                flow: flow.clone(),
                status,
                wire,
                packet: None,
                error,
                sources,
            },
            out,
        )?;
        self.buffered -= d.buffer.len() - d.offset;
        self.buffer_capacity -= d.buffer.capacity();
        d.buffer = Vec::new();
        d.offset = 0;
        d.sources = None;
        Ok(())
    }
    fn stop(
        &mut self,
        flow: &ScopedFlowKey,
        stream: u64,
        generation: u64,
        status: Status,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        self.stopped.insert(flow.clone(), (stream, generation));
        if let Some(mut d) = self.directions.remove(flow) {
            let result = if d.stream == stream && d.generation == generation {
                self.flush(flow, &mut d, status, None, out).map(|()| {
                    d.disabled = true;
                })
            } else {
                Ok(())
            };
            self.directions.insert(flow.clone(), d);
            result?;
        }
        Ok(())
    }
    fn opaque(&self, direction: &Direction) -> bool {
        self.connections
            .get(&direction.stream)
            .is_some_and(|connection| {
                connection.generation == direction.generation && connection.unsupported_amqp
            })
    }
}

fn compact_buffer(direction: &mut Direction) {
    if direction.offset > 0 {
        #[cfg(test)]
        BUFFER_STATS.with(|stats| {
            let (allocations, copied, peak) = stats.get();
            stats.set((
                allocations,
                copied + direction.buffer.len() - direction.offset,
                peak,
            ));
        });
        direction.buffer.copy_within(direction.offset.., 0);
        direction
            .buffer
            .truncate(direction.buffer.len() - direction.offset);
        direction.offset = 0;
    }
}

#[cfg(test)]
thread_local! {
    static BUFFER_STATS: std::cell::Cell<(usize, usize, usize)> = const { std::cell::Cell::new((0, 0, 0)) };
}
session::application_collector!();

#[cfg(test)]
mod tests;
