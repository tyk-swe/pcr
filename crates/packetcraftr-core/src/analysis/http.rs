// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sourced cleartext HTTP/1 messages over reassembled TCP.

use super::{
    FrameRecord, Summary as RunSummary,
    application::{self, Error, Limits, TcpSources},
    provenance::{Accumulator, SourceSet},
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
    pub fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
        let mut output = Vec::new();
        let summary = self.finalize(
            run,
            || Ok(()),
            |events| {
                output.extend(events);
                Ok(())
            },
        )?;
        Ok((output, summary))
    }

    fn finalize(
        mut self,
        run: &RunSummary,
        mut check: impl FnMut() -> Result<(), Error>,
        mut emit: impl FnMut(Vec<Event>) -> Result<(), Error>,
    ) -> Result<Summary, Error> {
        check()?;
        for event in self
            .tcp
            .trailing(&run.trailing_tcp_events, run.frames_read)?
        {
            check()?;
            let mut output = Vec::new();
            if let application::Event::Evicted { flow, .. } = event {
                self.stop(&flow, Status::Incomplete, false, &mut output)?;
            } else {
                self.event(event, run.frames_read, &mut output)?;
            }
            emit(output)?;
        }
        for (flow, mut direction) in std::mem::take(&mut self.directions) {
            check()?;
            let mut output = Vec::new();
            self.flush(&flow, &mut direction, Status::Incomplete, None, &mut output)?;
            emit(output)?;
        }
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
                    sources: Accumulator::new(&data.sources)?,
                });
            }
            let live = direction.live.as_mut().expect("initialized live message");
            if !merged {
                live.sources.insert(&data.sources)?;
                merged = true;
            }
            self.limits.check_source_spans(live.sources.len())?;
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
            sources: live.sources.freeze()?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{self, Session},
        budget::Deadline,
        build::Builder,
        capture_file::{Format, Reader, Writer},
        error::Classified,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, network::Ipv4, transport::Tcp},
        registry::Registry,
    };
    use std::{
        io::Cursor,
        net::{Ipv4Addr, SocketAddrV4},
        sync::Arc,
        time::{Duration, Instant, UNIX_EPOCH},
    };

    // HTTP/1 framing, informational responses and chunked trailers, checked 2026-10-25.
    // https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3
    // https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1
    const POST: &[u8] = b"POST /first HTTP/1.1\r\nHost: unit.test\r\nContent-Length: 3\r\n\r\n";
    const HEAD: &[u8] = b"HEAD /second HTTP/1.1\r\nHost: unit.test\r\n\r\n";
    const INFORMATIONAL: &[u8] = b"HTTP/1.1 103 Early Hints\r\nLink: </asset>\r\n\r\n";
    const CHUNKED: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n";
    const HEAD_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n";

    #[derive(Clone, Copy)]
    enum Lifecycle {
        Session,
        Direct,
    }

    fn registry() -> Arc<Registry> {
        Arc::new(
            builtin::registry_with(|builder| {
                builder.bind("tcp", 40000, "raw", i32::MAX)?;
                builder.bind("tcp", 8081, "raw", i32::MAX)?;
                Ok(())
            })
            .unwrap(),
        )
    }

    fn endpoints(response: bool) -> (SocketAddrV4, SocketAddrV4) {
        let client = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40000);
        let server = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 80), 8081);
        if response {
            (server, client)
        } else {
            (client, server)
        }
    }

    fn frame(number: u64, response: bool, mut header: Tcp, payload: &[u8]) -> Frame {
        let (source, destination) = endpoints(response);
        header.source_port = source.port();
        header.destination_port = destination.port();
        header.window = 4096;
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: *source.ip(),
            destination: *destination.ip(),
            ..Default::default()
        });
        packet.push(header);
        if !payload.is_empty() {
            packet.push(Raw::new(payload.to_vec()));
        }
        let built = Builder::new(registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        Frame::new(
            UNIX_EPOCH + Duration::from_secs(100 + number),
            LinkType::RAW,
            built.bytes,
        )
        .unwrap()
    }

    fn frames(client: &[&[u8]], server: &[&[u8]]) -> Vec<Frame> {
        let mut frames = vec![
            frame(
                1,
                false,
                Tcp {
                    sequence: 100,
                    flags: Tcp::SYN,
                    ..Default::default()
                },
                &[],
            ),
            frame(
                2,
                true,
                Tcp {
                    sequence: 900,
                    acknowledgment: 101,
                    flags: Tcp::SYN | Tcp::ACK,
                    ..Default::default()
                },
                &[],
            ),
            frame(
                3,
                false,
                Tcp {
                    sequence: 101,
                    acknowledgment: 901,
                    flags: Tcp::ACK,
                    ..Default::default()
                },
                &[],
            ),
        ];
        let mut client_sequence = 101;
        for payload in client {
            frames.push(frame(
                frames.len() as u64 + 1,
                false,
                Tcp {
                    sequence: client_sequence,
                    acknowledgment: 901,
                    flags: Tcp::ACK,
                    ..Default::default()
                },
                payload,
            ));
            client_sequence += u32::try_from(payload.len()).unwrap();
        }
        let mut server_sequence = 901;
        for payload in server {
            frames.push(frame(
                frames.len() as u64 + 1,
                true,
                Tcp {
                    sequence: server_sequence,
                    acknowledgment: client_sequence,
                    flags: Tcp::ACK,
                    ..Default::default()
                },
                payload,
            ));
            server_sequence += u32::try_from(payload.len()).unwrap();
        }
        frames
    }

    fn collect(
        frames: &[Frame],
        lifecycle: Lifecycle,
        max_buffer_bytes: usize,
    ) -> Result<(Vec<Event>, Summary, Vec<Definition>), analysis::Error> {
        let mut writer = Writer::new(Vec::new(), Format::Pcap, LinkType::RAW).unwrap();
        for frame in frames {
            writer.write_frame(frame).unwrap();
        }
        let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
        let collector = Collector::new(
            Limits {
                max_messages: 16,
                max_streams: 4,
                max_buffer_bytes,
                max_retained_bytes: 128 * 1024,
                max_source_spans: 16,
            },
            [8081],
            64,
        )
        .unwrap();
        let now = Instant::now();
        let options = analysis::Options {
            deadline: Some(Arc::new(Deadline::with_time_source(
                Duration::from_secs(30),
                move || now,
            ))),
            tcp_events: matches!(lifecycle, Lifecycle::Direct),
            track_sources: matches!(lifecycle, Lifecycle::Direct),
            limits: analysis::Limits {
                max_frames: 32,
                max_bytes: 64 * 1024,
                max_frame_bytes: 1024,
                max_duration: Duration::MAX,
                tcp: analysis::reassembly::tcp::Limits {
                    idle_expiry: Duration::from_secs(60),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut events = Vec::new();
        match lifecycle {
            Lifecycle::Session => {
                let outcome = Session::new(registry(), options, collector).run(
                    &mut reader,
                    |_| Ok(()),
                    |event| {
                        events.push(event);
                        Ok(())
                    },
                )?;
                Ok((events, outcome.summary, outcome.scopes))
            }
            Lifecycle::Direct => {
                let mut collector = collector;
                let run = analysis::run(&mut reader, registry(), &options, |record| {
                    events.extend(<Collector as analysis::Collector>::observe(
                        &mut collector,
                        &record,
                    )?);
                    Ok(())
                })?;
                let scopes = <Collector as analysis::Collector>::scopes(&collector);
                let (tail, summary) = <Collector as analysis::Collector>::finish(collector, &run)
                    .map_err(analysis::Error::Collector)?;
                events.extend(tail);
                Ok((events, summary, scopes))
            }
        }
    }

    fn messages(events: &[Event]) -> Vec<&Message> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Message(message) => Some(message.as_ref()),
                _ => None,
            })
            .collect()
    }

    fn source_numbers(sources: &SourceSet) -> Vec<u64> {
        sources.iter().map(|source| source.number).collect()
    }

    fn complete<'a>(
        message: &'a Message,
        header: &[u8],
        framing: Body,
        body_bytes: u64,
        sources: &[u64],
    ) -> &'a Head {
        assert_eq!(message.status, Status::Complete);
        assert_eq!(message.header_wire.as_ref(), header);
        assert_eq!(message.framing, Some(framing));
        assert_eq!(message.body_bytes, body_bytes);
        assert!(message.error.is_none());
        assert_eq!(source_numbers(&message.sources), sources);
        message.head.as_ref().unwrap()
    }

    #[test]
    fn pipelined_requests_keep_informational_pairing_chunked_trailers_and_head_framing() {
        let client_tail = [&POST[20..], b"abc", HEAD].concat();
        let server_head = [INFORMATIONAL, &CHUNKED[..15]].concat();
        let server_tail = [
            &CHUNKED[15..],
            b"3\r\nxyz\r\n0\r\nX-Trailer: complete\r\n\r\n",
            HEAD_RESPONSE,
        ]
        .concat();
        let frames = frames(&[&POST[..20], &client_tail], &[&server_head, &server_tail]);
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (events, summary, scopes) = collect(&frames, lifecycle, 512).unwrap();
            let messages = messages(&events);
            let [post, head, informational, chunked, head_response] = messages.as_slice() else {
                panic!("expected both requests, an informational response and both final responses")
            };
            let post_head = complete(post, POST, Body::Length(3), 3, &[4, 5]);
            assert!(
                matches!(&post_head.start, http::StartLine::Request { method, target, version }
                if method == "POST" && target.as_ref() == b"/first" && version == "HTTP/1.1")
            );
            assert_eq!(
                post_head.values("host").collect::<Vec<_>>(),
                [b"unit.test".as_slice()]
            );
            let head_head = complete(head, HEAD, Body::None, 0, &[5]);
            assert!(
                matches!(&head_head.start, http::StartLine::Request { method, target, .. }
                if method == "HEAD" && target.as_ref() == b"/second")
            );
            assert_eq!(
                complete(informational, INFORMATIONAL, Body::None, 0, &[6]).status(),
                Some(103)
            );
            assert_eq!(informational.request, Some(post.index));
            assert_eq!(
                complete(chunked, CHUNKED, Body::Chunked, 3, &[6, 7]).status(),
                Some(200)
            );
            assert_eq!(chunked.request, Some(post.index));
            let [trailer] = chunked.trailers.as_slice() else {
                panic!("expected the supplied chunked trailer")
            };
            assert!(trailer.name.eq_ignore_ascii_case("X-Trailer"));
            assert_eq!(trailer.value.as_ref(), b"complete");
            // A HEAD response has no message body, checked 2026-10-25.
            // https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2
            let response_head = complete(head_response, HEAD_RESPONSE, Body::None, 0, &[7]);
            assert_eq!(response_head.status(), Some(200));
            assert_eq!(
                response_head.values("content-length").collect::<Vec<_>>(),
                [b"7".as_slice()]
            );
            assert_eq!(head_response.request, Some(head.index));
            assert!(
                messages
                    .windows(2)
                    .all(|pair| pair[0].index < pair[1].index)
            );
            for message in &messages {
                assert!(scopes.iter().any(|scope| scope.id == message.flow.scope));
            }
            assert_eq!(
                (
                    summary.messages,
                    summary.complete_messages,
                    summary.incomplete_messages,
                    summary.malformed_messages,
                    summary.responses_without_request,
                    summary.requests_without_final_response,
                    summary.upgraded_connections,
                ),
                (5, 5, 0, 0, 0, 0, 0)
            );
        }
    }

    #[test]
    fn completed_headers_release_admission_and_eof_keeps_the_partial_successor() {
        let header = b"GET /small HTTP/1.1\r\nHost: unit.test\r\n\r\n";
        let partial = b"GET /later HTTP/1.1\r\nHost: pending";
        let split = header.len() - 1;
        let tail = [&header[split..], header.as_slice(), partial.as_slice()].concat();
        let frames = frames(&[&header[..split], &tail], &[]);
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (events, summary, scopes) = collect(&frames, lifecycle, header.len()).unwrap();
            let messages = messages(&events);
            let [first, second, unfinished] = messages.as_slice() else {
                panic!("expected two completed requests and the EOF partial header")
            };
            assert_eq!(
                complete(first, header, Body::None, 0, &[4, 5]).method(),
                Some("GET")
            );
            assert_eq!(
                complete(second, header, Body::None, 0, &[5]).method(),
                Some("GET")
            );
            assert_eq!(unfinished.status, Status::Incomplete);
            assert_eq!(unfinished.header_wire.as_ref(), partial);
            assert!(unfinished.head.is_none());
            assert_eq!(unfinished.framing, None);
            assert_eq!(unfinished.body_bytes, 0);
            assert!(unfinished.error.is_none());
            assert_eq!(source_numbers(&unfinished.sources), [5]);
            for message in &messages {
                assert!(scopes.iter().any(|scope| scope.id == message.flow.scope));
            }
            assert_eq!(
                (
                    summary.messages,
                    summary.complete_messages,
                    summary.incomplete_messages,
                    summary.malformed_messages,
                    summary.requests_without_final_response,
                ),
                (3, 2, 1, 0, 2)
            );
            let error = collect(&frames, lifecycle, header.len() - 1).unwrap_err();
            assert_eq!(error.classification().code, "policy.application_limit");
            let expected = format!("max_buffer_bytes={}", header.len() - 1);
            assert!(error.causes().iter().any(|cause| cause.contains(&expected)));
        }
    }
}
