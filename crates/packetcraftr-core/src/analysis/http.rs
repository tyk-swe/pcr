// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sourced cleartext HTTP/1 messages over reassembled TCP.

use super::{
    FrameRecord, ScopedFlowKey, Summary as RunSummary,
    application::{self, Error, Limits, Retained, TcpStreamFilter},
    provenance::{Accumulator, SourceSet},
    scope::Definition,
    session::{self, CollectorNeeds},
};
use crate::error::BoundaryError;
use crate::protocol::application::http::{self, Body, BodyDecoder, Head, Header};
use bytes::Bytes;
use memchr::memchr;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Incomplete,
    Malformed,
    Limit,
    Gap,
    Conflict,
    Reset,
    Evicted,
    Upgrade,
}
#[derive(Clone, Debug)]
pub struct Message {
    pub index: u64,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub request: Option<u64>,
    pub status: Status,
    pub head: Option<Head>,
    pub header_wire: Bytes,
    pub framing: Option<Body>,
    pub body_bytes: u64,
    pub trailers: Vec<Header>,
    pub error: Option<http::Error>,
    pub sources: SourceSet,
}
pub type Issue = application::StreamIssue<Status>;
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
    pub upgraded_connections: u64,
    pub responses_without_request: u64,
    pub requests_without_final_response: u64,
}
struct Pending {
    index: u64,
    method: String,
    first_frame: u64,
}
struct Live {
    index: u64,
    header: Vec<u8>,
    head: Option<Head>,
    body: Option<BodyDecoder>,
    framing: Option<Body>,
    request: Option<u64>,
    sources: Accumulator,
}
impl Live {
    fn buffered(&self) -> usize {
        self.header.len()
            + self.head.as_ref().map_or(0, |head| head.wire().len())
            + self.body.as_ref().map_or(0, BodyDecoder::buffered_bytes)
    }
}
struct Direction {
    stream: u64,
    generation: u64,
    disabled: bool,
    live: Option<Live>,
    deferred: VecDeque<Chunk>,
    deferred_bytes: usize,
    deferred_spans: usize,
    clean_closed: bool,
}
impl Direction {
    fn new(stream: u64, generation: u64) -> Self {
        Self {
            stream,
            generation,
            disabled: false,
            live: None,
            deferred: VecDeque::new(),
            deferred_bytes: 0,
            deferred_spans: 0,
            clean_closed: false,
        }
    }

    fn waiting(&self) -> bool {
        self.waiting_response().is_some()
    }

    fn waiting_response(&self) -> Option<(u64, u16)> {
        let live = self.live.as_ref()?;
        if live.body.is_some() {
            return None;
        }
        Some((live.sources.first()?.number, live.head.as_ref()?.status()?))
    }

    fn buffered(&self) -> usize {
        self.live.as_ref().map_or(0, Live::buffered) + self.deferred_bytes
    }

    fn pop(&mut self) -> Option<Chunk> {
        let chunk = self.deferred.pop_front()?;
        self.deferred_bytes -= Chunk::charge(chunk.bytes.len());
        self.deferred_spans -= chunk.sources.frames().len();
        Some(chunk)
    }

    fn discard_deferred(&mut self) {
        self.deferred.clear();
        self.deferred_bytes = 0;
        self.deferred_spans = 0;
    }
}
struct Chunk {
    bytes: Bytes,
    sources: SourceSet,
}
impl Chunk {
    fn charge(length: usize) -> usize {
        length * 2 + 2 * std::mem::size_of::<Self>()
    }
}
type Connection = (u64, u64);
type RequestKey = (Connection, ScopedFlowKey);
enum Work {
    Input(application::Delivery),
    Replay {
        flow: ScopedFlowKey,
        connection: Connection,
    },
}
enum Progress {
    Done,
    Wait(usize),
    WakePeer(usize),
}
pub struct Collector {
    limits: Limits,
    max_body_bytes: u64,
    tcp: TcpStreamFilter,
    directions: BTreeMap<ScopedFlowKey, Direction>,
    requests: BTreeMap<RequestKey, VecDeque<Pending>>,
    upgraded: BTreeSet<Connection>,
    generations: BTreeMap<u64, u64>,
    buffered: usize,
    retained: Retained,
    summary: Summary,
}
impl Collector {
    pub fn new(
        limits: Limits,
        ports: impl IntoIterator<Item = u16>,
        max_body_bytes: u64,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let ports = application::normalize_ports(ports, "http_ports")?;
        super::error::check_ceiling(
            "max_http_body_bytes",
            max_body_bytes,
            application::MAX_BODY_BYTES,
        )?;
        Ok(Self {
            limits,
            max_body_bytes,
            tcp: TcpStreamFilter::new(ports, limits),
            directions: BTreeMap::new(),
            requests: BTreeMap::new(),
            upgraded: BTreeSet::new(),
            generations: BTreeMap::new(),
            buffered: 0,
            retained: Retained::new(limits),
            summary: Summary::default(),
        })
    }
    pub fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.tcp.scopes()
    }
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        let mut output = Vec::new();
        for event in self.tcp.observe(record)? {
            self.event(event, record.number, &mut output)?;
        }
        Ok(output)
    }

    fn finalize(
        mut self,
        run: &RunSummary,
        mut check: impl FnMut() -> Result<(), Error>,
        mut emit: impl FnMut(Vec<Event>) -> Result<(), Error>,
    ) -> Result<Summary, Error> {
        check()?;
        let trailing = self
            .tcp
            .trailing(&run.trailing_tcp_events, run.frames_read)?;
        application::drain_batches(trailing, &mut check, &mut emit, |event, output| {
            if let application::Event::Evicted { flow, .. } = event {
                self.stop(&flow, Status::Incomplete, false, output)
            } else {
                self.event(event, run.frames_read, output)
            }
        })?;
        let directions = std::mem::take(&mut self.directions);
        application::drain_batches(
            directions,
            &mut check,
            &mut emit,
            |(flow, mut direction), output| {
                self.buffered -= direction.buffered();
                self.finish_direction(&flow, &mut direction, Status::Incomplete, output)
            },
        )?;
        for queue in self.requests.values() {
            check()?;
            self.summary.requests_without_final_response += queue.len() as u64;
        }
        check()?;
        Ok(self.summary)
    }
    fn event(
        &mut self,
        event: application::Event,
        number: u64,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let (flow, stream, status, clean) = match event {
            application::Event::Data(data) => return self.data(data, output),
            application::Event::Gap { flow, stream, .. } => (flow, stream, Status::Gap, false),
            application::Event::Conflict { flow, stream, .. } => {
                (flow, stream, Status::Conflict, false)
            }
            application::Event::Evicted { flow, stream, .. } => {
                (flow, stream, Status::Evicted, false)
            }
            application::Event::Closed {
                flow,
                stream,
                reset,
                ..
            } => (
                flow,
                stream,
                if reset {
                    Status::Reset
                } else {
                    Status::Incomplete
                },
                !reset,
            ),
        };
        if !clean {
            output.push(Event::Issue(Issue {
                number,
                flow: flow.clone(),
                stream,
                status,
            }));
        }
        self.stop(&flow, status, clean, output)?;
        if status == Status::Reset {
            self.stop(&flow.reverse(), status, false, output)?;
        }
        Ok(())
    }
    fn direction_for(
        &mut self,
        data: &application::Delivery,
        output: &mut Vec<Event>,
    ) -> Result<Direction, Error> {
        if self
            .generations
            .insert(data.stream, data.generation)
            .is_some_and(|old| old != data.generation)
        {
            self.upgraded.retain(|(stream, _)| *stream != data.stream);
            self.requests.retain(|((stream, _), _), queue| {
                if *stream == data.stream {
                    self.summary.requests_without_final_response += queue.len() as u64;
                    false
                } else {
                    true
                }
            });
        }
        let mut direction = self
            .directions
            .remove(&data.flow)
            .unwrap_or_else(|| Direction::new(data.stream, data.generation));
        self.buffered -= direction.buffered();
        if direction.generation != data.generation {
            self.finish_direction(&data.flow, &mut direction, Status::Evicted, output)?;
            direction = Direction::new(data.stream, data.generation);
        }
        Ok(direction)
    }

    fn data(&mut self, data: application::Delivery, output: &mut Vec<Event>) -> Result<(), Error> {
        let mut next = Some(Work::Input(data));
        let mut work = Vec::new();
        while let Some(next) = next.take().or_else(|| work.pop()) {
            let (flow, connection, mut direction, chunk, replaying) = match next {
                Work::Input(data) => {
                    let direction = self.direction_for(&data, output)?;
                    let chunk = Chunk {
                        bytes: data.bytes,
                        sources: data.sources,
                    };
                    (
                        data.flow,
                        (data.stream, data.generation),
                        direction,
                        Some(chunk),
                        false,
                    )
                }
                Work::Replay { flow, connection } => {
                    let Some(mut direction) = self.directions.remove(&flow) else {
                        continue;
                    };
                    if (direction.stream, direction.generation) != connection {
                        self.directions.insert(flow, direction);
                        continue;
                    }
                    self.buffered -= direction.buffered();
                    if direction.waiting() {
                        self.start_body(&flow, &mut direction, false, output)?;
                    }
                    let chunk = if direction.waiting() {
                        None
                    } else {
                        direction.pop()
                    };
                    (flow, connection, direction, chunk, true)
                }
            };

            let mut wake_peer = false;
            if let Some(chunk) = chunk {
                let progress = self.read(&flow, &mut direction, &chunk, false, output)?;
                if let Progress::Wait(consumed) | Progress::WakePeer(consumed) = progress {
                    wake_peer = matches!(progress, Progress::WakePeer(_));
                    if consumed < chunk.bytes.len()
                        && let Err(error) = self.defer(&mut direction, chunk, consumed, replaying)
                    {
                        if wake_peer {
                            return Err(error);
                        }
                        direction.discard_deferred();
                        self.flush(&flow, &mut direction, Status::Incomplete, None, output)?;
                        direction.disabled = true;
                    }
                }
            }

            if direction.disabled || self.upgraded.contains(&connection) {
                direction.discard_deferred();
            } else if !direction.waiting() {
                if !direction.deferred.is_empty() {
                    work.push(Work::Replay {
                        flow: flow.clone(),
                        connection,
                    });
                } else if direction.clean_closed {
                    self.close(&flow, &mut direction, output)?;
                }
            }
            if wake_peer {
                work.push(Work::Replay {
                    flow: flow.reverse(),
                    connection,
                });
            }
            self.check_buffer(direction.buffered())?;
            self.buffered += direction.buffered();
            self.directions.insert(flow, direction);
        }
        Ok(())
    }

    fn defer(
        &self,
        direction: &mut Direction,
        chunk: Chunk,
        consumed: usize,
        replaying: bool,
    ) -> Result<(), Error> {
        let charge = Chunk::charge(chunk.bytes.len() - consumed);
        let spans = direction.deferred_spans + chunk.sources.frames().len();
        self.limits.check_source_spans(spans)?;
        self.check_buffer(direction.buffered() + charge)?;
        let chunk = Chunk {
            bytes: Bytes::copy_from_slice(&chunk.bytes[consumed..]),
            sources: chunk.sources,
        };
        direction.deferred_bytes += charge;
        direction.deferred_spans = spans;
        if replaying {
            direction.deferred.push_front(chunk);
        } else {
            direction.deferred.push_back(chunk);
        }
        Ok(())
    }

    fn read(
        &mut self,
        flow: &ScopedFlowKey,
        direction: &mut Direction,
        chunk: &Chunk,
        ending: bool,
        output: &mut Vec<Event>,
    ) -> Result<Progress, Error> {
        let connection = (direction.stream, direction.generation);
        let mut input = chunk.bytes.as_ref();
        let mut merged = direction.live.is_none();
        while !input.is_empty() && !direction.disabled && !self.upgraded.contains(&connection) {
            if direction.waiting() {
                return Ok(Progress::Wait(chunk.bytes.len() - input.len()));
            }
            if direction.live.is_none() {
                self.limits.check_messages(self.summary.messages as usize)?;
                self.summary.messages += 1;
                direction.live = Some(Live {
                    index: self.summary.messages,
                    header: Vec::new(),
                    head: None,
                    body: None,
                    framing: None,
                    request: None,
                    sources: Accumulator::new(&chunk.sources)?,
                });
            }
            let live = direction.live.as_mut().expect("initialized live message");
            if !merged {
                live.sources.insert(&chunk.sources)?;
                merged = true;
            }
            self.limits.check_source_spans(live.sources.len())?;
            if live.head.is_some() {
                let consumed = self.consume_body(flow, direction, input, output)?;
                input = &input[consumed..];
                continue;
            }

            let run = &input[..memchr(b'\n', input).map_or(input.len(), |i| i + 1)];
            let bare = bare_crlf_offset(live.header.last().copied(), run);
            let room = (http::MAX_HEADER_BYTES + 1).saturating_sub(live.header.len());
            let take = run.len().min(room).min(bare.map_or(usize::MAX, |i| i + 1));
            self.check_buffer(direction.deferred_bytes + live.buffered() + take)?;
            live.header.extend_from_slice(&run[..take]);
            input = &input[take..];
            if live.header.len() > http::MAX_HEADER_BYTES {
                self.reject(
                    flow,
                    direction,
                    http::Error::Limit(http::Limit::HeaderBytes),
                    output,
                )?;
                continue;
            }
            if bare.is_some_and(|i| i < take) {
                self.reject(
                    flow,
                    direction,
                    http::Error::Invalid("header uses a bare CR or LF"),
                    output,
                )?;
                continue;
            }
            if !live.header.ends_with(b"\r\n\r\n") {
                continue;
            }
            self.retained.charge(live.header.len())?;
            let (head, _) = match http::parse_head(&Bytes::copy_from_slice(&live.header)) {
                Ok(Some(head)) => head,
                Ok(None) => unreachable!("terminator present"),
                Err(error) => {
                    self.reject(flow, direction, error, output)?;
                    continue;
                }
            };
            let mut wake_peer = false;
            if let Some(method) = head.method() {
                let first_frame = live.sources.first().expect("message has sources").number;
                self.requests
                    .entry((connection, flow.clone()))
                    .or_default()
                    .push_back(Pending {
                        index: live.index,
                        method: method.to_owned(),
                        first_frame,
                    });
                wake_peer = !ending
                    && self.directions.get(&flow.reverse()).is_some_and(|peer| {
                        (peer.stream, peer.generation) == connection
                            && peer.waiting_response().is_some_and(|(frame, status)| {
                                first_frame < frame || has_independent_framing(status)
                            })
                    });
            }
            live.header = Vec::new();
            live.head = Some(head);
            self.start_body(flow, direction, ending, output)?;
            if wake_peer {
                return Ok(Progress::WakePeer(chunk.bytes.len() - input.len()));
            }
        }
        Ok(Progress::Done)
    }

    fn start_body(
        &mut self,
        flow: &ScopedFlowKey,
        direction: &mut Direction,
        ending: bool,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let connection = (direction.stream, direction.generation);
        let live = direction.live.as_mut().expect("initialized live message");
        let head = live.head.as_ref().expect("parsed head");
        let method = match head.status() {
            Some(status) => {
                let key = (connection, flow.reverse());
                let first_frame = live.sources.first().expect("message has sources").number;
                match self.requests.get_mut(&key) {
                    Some(queue)
                        if queue
                            .front()
                            .is_some_and(|request| request.first_frame < first_frame) =>
                    {
                        let request = queue.front().expect("front request exists");
                        live.request = Some(request.index);
                        if status >= 200 || status == 101 {
                            let method = queue.pop_front().expect("front request exists").method;
                            if queue.is_empty() {
                                self.requests.remove(&key);
                            }
                            Some(method)
                        } else {
                            Some(request.method.clone())
                        }
                    }
                    None if !ending && status != 101 => return Ok(()),
                    _ if !has_independent_framing(status) => return Ok(()),
                    _ => None,
                }
            }
            None => None,
        };
        let framing = match head.body(method.as_deref()) {
            Ok(framing) => framing,
            Err(error) => return self.reject(flow, direction, error, output),
        };
        live.framing = Some(framing);
        live.body = Some(BodyDecoder::new(framing, self.max_body_bytes));
        if let Body::Length(length) = framing
            && length > self.max_body_bytes
        {
            return self.reject(
                flow,
                direction,
                http::Error::Limit(http::Limit::BodyBytes),
                output,
            );
        }
        if live.body.as_ref().is_some_and(BodyDecoder::complete) {
            let status = if framing == Body::Tunnel {
                self.upgraded.insert(connection);
                self.summary.upgraded_connections += 1;
                Status::Upgrade
            } else {
                Status::Complete
            };
            self.flush(flow, direction, status, None, output)?;
        }
        Ok(())
    }

    fn consume_body(
        &mut self,
        flow: &ScopedFlowKey,
        direction: &mut Direction,
        input: &[u8],
        output: &mut Vec<Event>,
    ) -> Result<usize, Error> {
        let live = direction.live.as_mut().expect("initialized live message");
        let growth = live
            .body
            .as_ref()
            .expect("head has body state")
            .additional_buffer_bound(input.len());
        self.check_buffer(direction.deferred_bytes + live.buffered().saturating_add(growth))?;
        match live
            .body
            .as_mut()
            .expect("head has body state")
            .consume(input)
        {
            Ok(progress) => {
                if progress.complete {
                    self.flush(flow, direction, Status::Complete, None, output)?;
                }
                Ok(progress.consumed)
            }
            Err(error) => {
                self.reject(flow, direction, error, output)?;
                Ok(0)
            }
        }
    }

    fn reject(
        &mut self,
        flow: &ScopedFlowKey,
        direction: &mut Direction,
        error: http::Error,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        self.flush(flow, direction, failure_status(&error), Some(error), output)?;
        direction.disabled = true;
        Ok(())
    }

    fn check_buffer(&self, current: usize) -> Result<(), Error> {
        self.limits
            .check_buffer(self.buffered.saturating_add(current))
    }
    fn stop(
        &mut self,
        flow: &ScopedFlowKey,
        status: Status,
        clean: bool,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if let Some(mut direction) = self.directions.remove(flow) {
            self.buffered -= direction.buffered();
            if clean && direction.waiting() {
                direction.clean_closed = true;
            } else if clean {
                self.close(flow, &mut direction, output)?;
            } else {
                self.finish_direction(flow, &mut direction, status, output)?;
            }
            self.buffered += direction.buffered();
            self.directions.insert(flow.clone(), direction);
        }
        Ok(())
    }
    fn finish_direction(
        &mut self,
        flow: &ScopedFlowKey,
        direction: &mut Direction,
        status: Status,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if direction.waiting() {
            self.start_body(flow, direction, true, output)?;
            let connection = (direction.stream, direction.generation);
            while !direction.waiting()
                && !direction.disabled
                && !self.upgraded.contains(&connection)
            {
                let Some(chunk) = direction.pop() else {
                    break;
                };
                self.read(flow, direction, &chunk, true, output)?;
            }
        }
        direction.discard_deferred();
        if status == Status::Incomplete && direction.clean_closed {
            return self.close(flow, direction, output);
        }
        self.flush(flow, direction, status, None, output)?;
        direction.disabled = true;
        Ok(())
    }
    fn close(
        &mut self,
        flow: &ScopedFlowKey,
        direction: &mut Direction,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let complete = direction
            .live
            .as_mut()
            .and_then(|live| live.body.as_mut())
            .is_some_and(BodyDecoder::close);
        let status = if complete {
            Status::Complete
        } else {
            Status::Incomplete
        };
        self.flush(flow, direction, status, None, output)?;
        direction.disabled = true;
        Ok(())
    }
    fn flush(
        &mut self,
        flow: &ScopedFlowKey,
        direction: &mut Direction,
        status: Status,
        error: Option<http::Error>,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let Some(live) = direction.live.take() else {
            return Ok(());
        };
        if live.request.is_none() && live.head.as_ref().and_then(Head::status).is_some() {
            self.summary.responses_without_request += 1;
        }
        match status {
            Status::Complete | Status::Upgrade => self.summary.complete_messages += 1,
            Status::Malformed | Status::Limit => self.summary.malformed_messages += 1,
            _ => self.summary.incomplete_messages += 1,
        }
        let extra = live
            .body
            .as_ref()
            .map_or(0, BodyDecoder::buffered_bytes)
            .saturating_add(if live.head.is_none() {
                live.header.len()
            } else {
                0
            });
        self.retained.charge(extra)?;
        let header_wire = live
            .head
            .as_ref()
            .map_or_else(|| Bytes::from(live.header), |head| head.wire().clone());
        let body_bytes = live.body.as_ref().map_or(0, BodyDecoder::body_bytes);
        let trailers = live
            .body
            .as_ref()
            .map_or_else(Vec::new, |body| body.trailers().to_vec());
        output.push(Event::Message(Box::new(Message {
            index: live.index,
            stream: direction.stream,
            generation: direction.generation,
            flow: flow.clone(),
            request: live.request,
            status,
            head: live.head,
            header_wire,
            framing: live.framing,
            body_bytes,
            trailers,
            error,
            sources: live.sources.freeze()?,
        })));
        Ok(())
    }
}

session::application_collector!();

fn has_independent_framing(status: u16) -> bool {
    matches!(status, 100..=199 | 304)
}

fn bare_crlf_offset(prev: Option<u8>, run: &[u8]) -> Option<usize> {
    if prev == Some(b'\r') && run.first() != Some(&b'\n') {
        return Some(0);
    }
    if let Some(cr) = memchr(b'\r', run) {
        return match run.get(cr + 1) {
            Some(&b'\n') | None => None,
            Some(_) => Some(cr + 1),
        };
    }
    if run.last() == Some(&b'\n') {
        let before = if run.len() >= 2 {
            Some(run[run.len() - 2])
        } else {
            prev
        };
        if before != Some(b'\r') {
            return Some(run.len() - 1);
        }
    }
    None
}

/// A parser refusal past a fixed bound is a limit, not malformed framing.
fn failure_status(error: &http::Error) -> Status {
    if matches!(error, http::Error::Limit(_)) {
        Status::Limit
    } else {
        Status::Malformed
    }
}
