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
            framer: Framer::new(protocol.as_str()),
            sources: None,
            disabled: false,
        }
    }
}

#[derive(Clone, Copy)]
struct Connection {
    generation: u64,
    protocol: Option<BuiltinProtocol>,
    mqtt_level: Option<u8>,
}

pub struct Collector {
    limits: Limits,
    registry: Arc<Registry>,
    selected: BTreeSet<BuiltinProtocol>,
    tcp: TcpSources,
    connections: BTreeMap<u64, Connection>,
    directions: BTreeMap<ScopedFlowKey, Direction>,
    buffered: usize,
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
            buffered: 0,
            retained: 0,
            summary: Summary::default(),
        })
    }
    pub fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.tcp.scopes.values()
    }
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        let mut events = Vec::new();
        for event in self.tcp.observe(record)? {
            self.event(event, record.number, &mut events)?;
        }
        Ok(events)
    }
    pub fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
        let mut out = Vec::new();
        let summary = self.finalize(
            run,
            || Ok(()),
            |events| {
                out.extend(events);
                Ok(())
            },
        )?;
        Ok((out, summary))
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
            if let application::Event::Evicted { flow, .. } = event {
                self.stop(&flow, Status::Incomplete, &mut out)?;
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
        let (flow, stream, status) = match event {
            application::Event::Data(data) => return self.data(data, out),
            application::Event::Gap { flow, stream } => (flow, stream, Status::Gap),
            application::Event::Conflict { flow, stream } => (flow, stream, Status::Conflict),
            application::Event::Evicted { flow, stream } => (flow, stream, Status::Evicted),
            application::Event::Closed {
                flow,
                stream,
                reset,
            } => (
                flow,
                stream,
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
        self.stop(&flow, status, out)?;
        if status == Status::Reset {
            self.stop(&flow.reverse(), status, out)?;
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
            .find_map(|port| {
                self.registry
                    .child_for("tcp", Discriminator(u64::from(port)))
                    .and_then(BuiltinProtocol::from_id)
                    .filter(|p| self.selected.contains(p))
            });
        self.connections.insert(
            data.stream,
            Connection {
                generation: data.generation,
                protocol: p,
                mqtt_level: None,
            },
        );
        p
    }
    fn data(&mut self, data: application::Delivery, out: &mut Vec<Event>) -> Result<(), Error> {
        let Some(protocol) = self.select(&data) else {
            return Ok(());
        };
        let mut d = self
            .directions
            .remove(&data.flow)
            .unwrap_or_else(|| Direction::new(data.stream, data.generation, protocol));
        if d.generation != data.generation {
            self.flush(&data.flow, &mut d, Status::Evicted, None, out)?;
            d = Direction::new(data.stream, data.generation, protocol);
        }
        if !d.disabled {
            self.limits
                .check_buffer(self.buffered.saturating_add(data.bytes.len()))?;
            d.buffer
                .try_reserve(data.bytes.len())
                .map_err(|_| Error::Limit {
                    field: "max_buffer_bytes",
                    limit: self.limits.max_buffer_bytes,
                })?;
            d.buffer.extend_from_slice(&data.bytes);
            self.buffered += data.bytes.len();
            if let Some(sources) = d.sources.as_mut() {
                sources.insert(&data.sources)?;
            } else {
                d.sources = Some(Accumulator::new(&data.sources)?);
            }
            self.limits
                .check_source_spans(d.sources.as_ref().unwrap().len())?;
            let mut offset = 0;
            while offset < d.buffer.len() && !d.disabled {
                match d
                    .framer
                    .progress(&d.buffer[offset..], self.limits.max_buffer_bytes)
                {
                    Ok(Some(len)) => {
                        if len == 0 {
                            return Err(Error::Limit {
                                field: "zero_length_message",
                                limit: 0,
                            });
                        }
                        let wire = Bytes::copy_from_slice(&d.buffer[offset..offset + len]);
                        let sources = d
                            .sources
                            .take()
                            .expect("buffered message has sources")
                            .freeze()?;
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
                        offset += len;
                        self.buffered -= len;
                        d.framer = Framer::new(d.protocol.as_str());
                        if offset < d.buffer.len() {
                            d.sources = Some(Accumulator::new(&data.sources)?);
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let status = if matches!(error, crate::codec::Error::Unsupported { .. }) {
                            Status::Unsupported
                        } else {
                            Status::Malformed
                        };
                        let tail = d.buffer[offset..].to_vec();
                        d.buffer = tail;
                        self.flush(&data.flow, &mut d, status, Some(error.to_string()), out)?;
                        offset = 0;
                        d.disabled = true;
                    }
                }
            }
            if offset > 0 {
                d.buffer = d.buffer[offset..].to_vec();
            }
        }
        self.directions.insert(data.flow, d);
        Ok(())
    }
    fn decode(&mut self, message: &mut Message) {
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
            parent: Some(crate::layer::Id::new("tcp")),
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
                if let Some(modbus) =
                    layer.downcast_mut::<crate::protocol::application::modbus_tcp::ModbusTcp>()
                {
                    let response = self.registry.child_for(
                        "tcp",
                        Discriminator(u64::from(message.flow.flow.source_port)),
                    ) == Some(crate::layer::Id::new("modbus_tcp"));
                    if let Err(error) = modbus.interpret(response) {
                        message.status = Status::Malformed;
                        message.error = Some(error.to_string());
                        return;
                    }
                }
                let mut p = Packet::new();
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
        self.retained = self
            .retained
            .saturating_add(Limits::decoded_charge(message.wire.len()));
        self.limits.check_retained(self.retained)?;
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
        status: Status,
        error: Option<String>,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if d.buffer.is_empty() {
            return Ok(());
        }
        self.buffered -= d.buffer.len();
        let wire = Bytes::from(std::mem::take(&mut d.buffer));
        let sources = d
            .sources
            .take()
            .expect("buffered bytes have sources")
            .freeze()?;
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
        )
    }
    fn stop(
        &mut self,
        flow: &ScopedFlowKey,
        status: Status,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if let Some(mut d) = self.directions.remove(flow) {
            self.flush(flow, &mut d, status, None, out)?;
            d.disabled = true;
            self.directions.insert(flow.clone(), d);
        }
        Ok(())
    }
}
impl session::Collector for Collector {
    type Event = Event;
    type Summary = Summary;
    fn needs(&self) -> CollectorNeeds {
        CollectorNeeds {
            tcp_stream: true,
            tcp_events: true,
            track_sources: true,
            ..CollectorNeeds::default()
        }
    }
    fn scopes(&self) -> Vec<Definition> {
        Self::scopes(self).cloned().collect()
    }
    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, BoundaryError> {
        Self::observe(self, record).map_err(BoundaryError::from_error)
    }
    fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), BoundaryError> {
        Self::finish(self, run).map_err(BoundaryError::from_error)
    }
    fn finish_controlled(
        self,
        run: &RunSummary,
        deadline: &crate::budget::Deadline,
        event_sink: &mut dyn FnMut(Event) -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        self.finalize(
            run,
            || session::check(deadline).map_err(Error::Output),
            |events| session::deliver(deadline, events, event_sink).map_err(Error::Output),
        )
        .map_err(BoundaryError::from_error)
    }
}

#[cfg(test)]
mod tests;
