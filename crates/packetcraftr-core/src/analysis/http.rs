// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sourced cleartext HTTP/1 messages over reassembled TCP.

use super::{
    FrameRecord, Summary as RunSummary,
    application::{self, Error, Limits, TcpSources},
    provenance::SourceSet,
    reassembly::tcp::ScopedFlowKey,
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
    pub upgraded_connections: u64,
    pub responses_without_request: u64,
    pub requests_without_final_response: u64,
}
struct Pending {
    index: u64,
    method: String,
}
struct Live {
    index: u64,
    header: Vec<u8>,
    head: Option<Head>,
    body: Option<BodyDecoder>,
    framing: Option<Body>,
    request: Option<u64>,
    sources: SourceSet,
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
}
impl Direction {
    fn new(stream: u64, generation: u64) -> Self {
        Self {
            stream,
            generation,
            disabled: false,
            live: None,
        }
    }
}
type Connection = (u64, u64);
type RequestKey = (Connection, ScopedFlowKey);
pub struct Collector {
    limits: Limits,
    max_body_bytes: u64,
    tcp: TcpSources,
    directions: BTreeMap<ScopedFlowKey, Direction>,
    requests: BTreeMap<RequestKey, VecDeque<Pending>>,
    upgraded: BTreeSet<Connection>,
    generations: BTreeMap<u64, u64>,
    buffered: usize,
    retained: usize,
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
        super::error::check_ceiling("max_http_body_bytes", max_body_bytes, 256 * 1024 * 1024)?;
        Ok(Self {
            limits,
            max_body_bytes,
            tcp: TcpSources::new(ports, limits),
            directions: BTreeMap::new(),
            requests: BTreeMap::new(),
            upgraded: BTreeSet::new(),
            generations: BTreeMap::new(),
            buffered: 0,
            retained: 0,
            summary: Summary::default(),
        })
    }
    pub fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.tcp.scopes.values()
    }
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        let mut output = Vec::new();
        for event in self.tcp.observe(record)? {
            self.event(event, record.number, &mut output)?;
        }
        Ok(output)
    }
    pub fn finish(mut self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
        let mut output = Vec::new();
        for event in self
            .tcp
            .trailing(&run.trailing_tcp_events, run.frames_read)?
        {
            if let application::Event::Evicted { flow, .. } = event {
                self.stop(&flow, Status::Incomplete, false, &mut output)?;
            } else {
                self.event(event, run.frames_read, &mut output)?;
            }
        }
        for (flow, mut direction) in std::mem::take(&mut self.directions) {
            self.flush(&flow, &mut direction, Status::Incomplete, None, &mut output)?;
        }
        self.summary.requests_without_final_response += self
            .requests
            .values()
            .map(|queue| queue.len() as u64)
            .sum::<u64>();
        Ok((output, self.summary))
    }
    fn event(
        &mut self,
        event: application::Event,
        number: u64,
        output: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let (flow, stream, status, clean) = match event {
            application::Event::Data(data) => return self.data(data, output),
            application::Event::Gap { flow, stream } => (flow, stream, Status::Gap, false),
            application::Event::Conflict { flow, stream } => {
                (flow, stream, Status::Conflict, false)
            }
            application::Event::Evicted { flow, stream } => (flow, stream, Status::Evicted, false),
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
        self.buffered -= direction.live.as_ref().map_or(0, Live::buffered);
        if direction.generation != data.generation {
            self.flush(&data.flow, &mut direction, Status::Evicted, None, output)?;
            direction = Direction::new(data.stream, data.generation);
        }
        Ok(direction)
    }

    fn data(&mut self, data: application::Delivery, output: &mut Vec<Event>) -> Result<(), Error> {
        let connection = (data.stream, data.generation);
        let mut direction = self.direction_for(&data, output)?;
        let mut input = data.bytes.as_ref();
        let mut merged = direction.live.is_none();
        let mut upgraded = self.upgraded.contains(&connection);
        while !input.is_empty() && !direction.disabled && !upgraded {
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
                    sources: data.sources.clone(),
                });
            }
            let live = direction.live.as_mut().expect("initialized live message");
            if !merged {
                live.sources = live.sources.union(&data.sources)?;
                merged = true;
            }
            self.limits
                .check_source_spans(live.sources.frames().len())?;
            if live.head.is_none() {
                // A run ends at the next LF (or consumes the input):
                // CR/LF pairing and the CRLFCRLF terminator can only
                // complete on an LF, so interior bytes append unchecked.
                let run = &input[..memchr(b'\n', input).map_or(input.len(), |i| i + 1)];
                let bare = bare_crlf_offset(live.header.last().copied(), run);
                let room = (http::MAX_HEADER_BYTES + 1).saturating_sub(live.header.len());
                let take = run.len().min(room).min(bare.map_or(usize::MAX, |i| i + 1));
                self.check_buffer(live.buffered().saturating_add(take))?;
                live.header.extend_from_slice(&run[..take]);
                input = &input[take..];
                if live.header.len() > http::MAX_HEADER_BYTES {
                    self.reject(
                        &data.flow,
                        &mut direction,
                        http::Error::Limit(http::Limit::HeaderBytes),
                        output,
                    )?;
                    continue;
                }
                if bare.is_some_and(|i| i < take) {
                    self.reject(
                        &data.flow,
                        &mut direction,
                        http::Error::Invalid("header uses a bare CR or LF"),
                        output,
                    )?;
                    continue;
                }
                if !live.header.ends_with(b"\r\n\r\n") {
                    continue;
                }
                self.retained = self
                    .retained
                    .saturating_add(Limits::decoded_charge(live.header.len()));
                self.limits.check_retained(self.retained)?;
                let parsed = http::parse_head(&Bytes::copy_from_slice(&live.header));
                let (head, _) = match parsed {
                    Ok(Some(head)) => head,
                    Ok(None) => unreachable!("terminator present"),
                    Err(error) => {
                        self.reject(&data.flow, &mut direction, error, output)?;
                        continue;
                    }
                };
                let request_method = self.pair_request(connection, &data.flow, &head, live);
                let framing = head.body(request_method.as_deref());
                live.header.clear();
                live.head = Some(head);
                let framing = match framing {
                    Ok(framing) => framing,
                    Err(error) => {
                        self.reject(&data.flow, &mut direction, error, output)?;
                        continue;
                    }
                };
                live.framing = Some(framing);
                live.body = Some(BodyDecoder::new(framing, self.max_body_bytes));
                if let Body::Length(length) = framing
                    && length > self.max_body_bytes
                {
                    self.reject(
                        &data.flow,
                        &mut direction,
                        http::Error::Limit(http::Limit::BodyBytes),
                        output,
                    )?;
                    continue;
                }
                if live.body.as_ref().is_some_and(BodyDecoder::complete) {
                    let status = if framing == Body::Tunnel {
                        upgraded = true;
                        self.upgraded.insert(connection);
                        self.summary.upgraded_connections += 1;
                        Status::Upgrade
                    } else {
                        Status::Complete
                    };
                    self.flush(&data.flow, &mut direction, status, None, output)?;
                }
            } else {
                let consumed = self.consume_body(&data.flow, &mut direction, input, output)?;
                input = &input[consumed..];
            }
        }
        self.check_buffer(direction.live.as_ref().map_or(0, Live::buffered))?;
        self.buffered += direction.live.as_ref().map_or(0, Live::buffered);
        self.directions.insert(data.flow, direction);
        Ok(())
    }

    fn pair_request(
        &mut self,
        connection: Connection,
        flow: &ScopedFlowKey,
        head: &Head,
        live: &mut Live,
    ) -> Option<String> {
        let mut request_method = None;
        if head.status().is_some() {
            let key = (connection, flow.reverse());
            if let Some(queue) = self.requests.get_mut(&key) {
                if let Some(request) = queue.front() {
                    live.request = Some(request.index);
                    request_method = Some(request.method.clone());
                }
                if head
                    .status()
                    .is_some_and(|status| status >= 200 || status == 101)
                {
                    queue.pop_front();
                }
                if queue.is_empty() {
                    self.requests.remove(&key);
                }
            }
            if live.request.is_none() {
                self.summary.responses_without_request += 1;
            }
        } else if let Some(method) = head.method() {
            self.requests
                .entry((connection, flow.clone()))
                .or_default()
                .push_back(Pending {
                    index: live.index,
                    method: method.to_owned(),
                });
        }
        request_method
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
        self.check_buffer(live.buffered().saturating_add(growth))?;
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
            self.buffered -= direction.live.as_ref().map_or(0, Live::buffered);
            let complete = clean
                && direction
                    .live
                    .as_mut()
                    .and_then(|live| live.body.as_mut())
                    .is_some_and(BodyDecoder::close);
            self.flush(
                flow,
                &mut direction,
                if complete { Status::Complete } else { status },
                None,
                output,
            )?;
            direction.disabled = true;
            self.directions.insert(flow.clone(), direction);
        }
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
        match status {
            Status::Complete | Status::Upgrade => self.summary.complete_messages += 1,
            Status::Malformed | Status::Limit => self.summary.malformed_messages += 1,
            _ => self.summary.incomplete_messages += 1,
        }
        let extra = Limits::decoded_charge(
            live.body
                .as_ref()
                .map_or(0, BodyDecoder::buffered_bytes)
                .saturating_add(if live.head.is_none() {
                    live.header.len()
                } else {
                    0
                }),
        );
        self.retained = self.retained.saturating_add(extra);
        self.limits.check_retained(self.retained)?;
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
            sources: live.sources,
        })));
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
