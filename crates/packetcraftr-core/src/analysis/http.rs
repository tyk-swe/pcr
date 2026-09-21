// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sourced cleartext HTTP/1 messages over reassembled TCP. Body bytes are counted
//! without retaining or decompressing content. Feed complete conversations.

use super::{
    FrameRecord, Summary as RunSummary,
    application::{self, Error, Limits, TcpSources},
    provenance::SourceSet,
    reassembly::tcp::ScopedFlowKey,
    scope::Definition,
};
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
    /// The request message index associated with this response, if captured.
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
        if max_body_bytes == 0 || max_body_bytes > 256 * 1024 * 1024 {
            return Err(Error::Limit {
                field: "max_http_body_bytes",
                limit: 256 * 1024 * 1024,
            });
        }
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
    /// Returns the direction state for this delivery, flushing and resetting
    /// retained state when a reused stream carries a new generation.
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
        let mut direction = self.directions.remove(&data.flow).unwrap_or(Direction {
            stream: data.stream,
            generation: data.generation,
            disabled: false,
            live: None,
        });
        self.buffered -= direction.live.as_ref().map_or(0, Live::buffered);
        if direction.generation != data.generation {
            self.flush(&data.flow, &mut direction, Status::Evicted, None, output)?;
            direction = Direction {
                stream: data.stream,
                generation: data.generation,
                disabled: false,
                live: None,
            };
        }
        Ok(direction)
    }

    fn data(&mut self, data: application::Delivery, output: &mut Vec<Event>) -> Result<(), Error> {
        let connection = (data.stream, data.generation);
        let mut direction = self.direction_for(&data, output)?;
        let mut input = data.bytes.as_ref();
        // A message still open from an earlier delivery merges this
        // delivery's sources once; a message this delivery opens already
        // starts from its set.
        let mut merged = direction.live.is_none();
        let mut upgraded = self.upgraded.contains(&connection);
        while !input.is_empty() && !direction.disabled && !upgraded {
            if direction.live.is_none() {
                if self.summary.messages as usize >= self.limits.max_messages {
                    return Err(Error::Limit {
                        field: "max_messages",
                        limit: self.limits.max_messages,
                    });
                }
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
            if live.sources.frames().len() > self.limits.max_source_spans {
                return Err(Error::Limit {
                    field: "max_source_spans",
                    limit: self.limits.max_source_spans,
                });
            }
            if live.head.is_none() {
                // A run ends at the next LF (or consumes the input):
                // CR/LF pairing and the CRLFCRLF terminator can only
                // complete on an LF, so interior bytes append unchecked.
                let run = &input[..memchr(b'\n', input).map_or(input.len(), |i| i + 1)];
                let bare = bare_crlf_offset(live.header.last().copied(), run);
                // The byte that first exceeds MAX_HEADER_BYTES is the last
                // one appended; inside a run it precedes the other checks.
                let room = (http::MAX_HEADER_BYTES + 1).saturating_sub(live.header.len());
                let take = run.len().min(room).min(bare.map_or(usize::MAX, |i| i + 1));
                self.check_buffer(live.buffered().saturating_add(take))?;
                live.header.extend_from_slice(&run[..take]);
                input = &input[take..];
                if live.header.len() > http::MAX_HEADER_BYTES {
                    self.flush(
                        &data.flow,
                        &mut direction,
                        Status::Limit,
                        Some(http::Error::Limit("header bytes")),
                        output,
                    )?;
                    direction.disabled = true;
                    continue;
                }
                if bare.is_some_and(|i| i < take) {
                    self.flush(
                        &data.flow,
                        &mut direction,
                        Status::Malformed,
                        Some(http::Error::Invalid("header uses a bare CR or LF")),
                        output,
                    )?;
                    direction.disabled = true;
                    continue;
                }
                if !live.header.ends_with(b"\r\n\r\n") {
                    continue;
                }
                self.retained = self
                    .retained
                    .saturating_add(live.header.len().saturating_mul(32))
                    .saturating_add(4096);
                if self.retained > self.limits.max_retained_bytes {
                    return Err(Error::Limit {
                        field: "max_retained_bytes",
                        limit: self.limits.max_retained_bytes,
                    });
                }
                let parsed = http::parse_head(&live.header);
                let (head, _) = match parsed {
                    Ok(Some(head)) => head,
                    Ok(None) => unreachable!("terminator present"),
                    Err(error) => {
                        self.flush(
                            &data.flow,
                            &mut direction,
                            Status::Malformed,
                            Some(error),
                            output,
                        )?;
                        direction.disabled = true;
                        continue;
                    }
                };
                let mut request_method = None;
                if head.status().is_some() {
                    let key = (connection, data.flow.reverse());
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
                        .entry((connection, data.flow.clone()))
                        .or_default()
                        .push_back(Pending {
                            index: live.index,
                            method: method.to_owned(),
                        });
                }
                let framing = head.body(request_method.as_deref());
                live.header.clear();
                live.head = Some(head);
                let framing = match framing {
                    Ok(framing) => framing,
                    Err(error) => {
                        self.flush(
                            &data.flow,
                            &mut direction,
                            Status::Malformed,
                            Some(error),
                            output,
                        )?;
                        direction.disabled = true;
                        continue;
                    }
                };
                live.framing = Some(framing);
                live.body = Some(BodyDecoder::new(framing, self.max_body_bytes));
                if let Body::Length(length) = framing
                    && length > self.max_body_bytes
                {
                    self.flush(
                        &data.flow,
                        &mut direction,
                        Status::Limit,
                        Some(http::Error::Limit("body bytes")),
                        output,
                    )?;
                    direction.disabled = true;
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
                        input = &input[progress.consumed..];
                        if progress.complete {
                            self.flush(&data.flow, &mut direction, Status::Complete, None, output)?;
                        }
                    }
                    Err(error) => {
                        let status = if matches!(error, http::Error::Limit(_)) {
                            Status::Limit
                        } else {
                            Status::Malformed
                        };
                        self.flush(&data.flow, &mut direction, status, Some(error), output)?;
                        direction.disabled = true;
                    }
                }
            }
        }
        self.check_buffer(direction.live.as_ref().map_or(0, Live::buffered))?;
        self.buffered += direction.live.as_ref().map_or(0, Live::buffered);
        self.directions.insert(data.flow, direction);
        Ok(())
    }

    fn check_buffer(&self, current: usize) -> Result<(), Error> {
        if self.buffered.saturating_add(current) > self.limits.max_buffer_bytes {
            return Err(Error::Limit {
                field: "max_buffer_bytes",
                limit: self.limits.max_buffer_bytes,
            });
        }
        Ok(())
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
        let extra = live
            .body
            .as_ref()
            .map_or(0, BodyDecoder::buffered_bytes)
            .saturating_add(if live.head.is_none() {
                live.header.len()
            } else {
                0
            })
            .saturating_mul(32)
            .saturating_add(4096);
        self.retained = self.retained.saturating_add(extra);
        if self.retained > self.limits.max_retained_bytes {
            return Err(Error::Limit {
                field: "max_retained_bytes",
                limit: self.limits.max_retained_bytes,
            });
        }
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
/// Offset in `run` of the first byte that breaks header CR/LF pairing, or
/// `None` when the run is clean. `run` covers the bytes through the next LF
/// (or the rest of the input), so its last byte is the only possible LF;
/// `prev` is the last buffered header byte, which may be a CR still
/// awaiting its LF.
fn bare_crlf_offset(prev: Option<u8>, run: &[u8]) -> Option<usize> {
    if prev == Some(b'\r') && run.first() != Some(&b'\n') {
        return Some(0);
    }
    if let Some(cr) = memchr(b'\r', run) {
        // The run's first CR decides: only a following LF pairs it, while
        // a CR ending the run still awaits its pair.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{
        provenance::{SourceFrame, Tracker},
        reassembly::tcp::FlowKey,
        scope::Interner,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, SystemTime};

    fn flow() -> ScopedFlowKey {
        let scope = Interner::new()
            .intern(None, Vec::new())
            .expect("scope interns");
        ScopedFlowKey {
            scope,
            flow: FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                source_port: 40_000,
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                destination_port: 80,
            },
        }
    }

    fn delivery(
        tracker: &Tracker,
        flow: &ScopedFlowKey,
        number: u64,
        bytes: &'static [u8],
    ) -> application::Delivery {
        application::Delivery {
            flow: flow.clone(),
            stream: 1,
            generation: 0,
            bytes: Bytes::from_static(bytes),
            sources: tracker
                .single(SourceFrame {
                    number,
                    timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(number),
                })
                .expect("source set"),
        }
    }

    fn messages(output: &[Event]) -> Vec<&Message> {
        output
            .iter()
            .filter_map(|event| match event {
                Event::Message(message) => Some(message.as_ref()),
                Event::Issue(_) => None,
            })
            .collect()
    }

    #[test]
    fn carried_message_merges_each_delivery_once() {
        let tracker = Tracker::new(1 << 20, 8).expect("tracker");
        let flow = flow();
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        let mut output = Vec::new();

        let baseline = tracker.union_reservations();
        collector
            .data(delivery(&tracker, &flow, 4, b"GET /lo"), &mut output)
            .expect("first header bytes");
        collector
            .data(
                delivery(&tracker, &flow, 5, b"ng HTTP/1.1\r\nHost: exa"),
                &mut output,
            )
            .expect("continuation bytes");
        collector
            .data(
                delivery(&tracker, &flow, 6, b"mple.test\r\n\r\n"),
                &mut output,
            )
            .expect("final header bytes");

        assert_eq!(
            tracker.union_reservations() - baseline,
            2,
            "one merge per contributing delivery, not per byte"
        );
        let messages = messages(&output);
        let [message] = messages.as_slice() else {
            panic!("one complete message expected, got {}", messages.len());
        };
        assert_eq!(message.status, Status::Complete);
        assert_eq!(
            message
                .sources
                .frames()
                .iter()
                .map(|frame| frame.number)
                .collect::<Vec<_>>(),
            [4, 5, 6]
        );
    }

    #[test]
    fn pipelined_messages_open_with_the_delivery_set_without_merging() {
        let tracker = Tracker::new(1 << 20, 8).expect("tracker");
        let flow = flow();
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        let mut output = Vec::new();

        let baseline = tracker.union_reservations();
        collector
            .data(
                delivery(
                    &tracker,
                    &flow,
                    9,
                    b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
                ),
                &mut output,
            )
            .expect("pipelined requests");

        assert_eq!(tracker.union_reservations(), baseline);
        let messages = messages(&output);
        assert_eq!(messages.len(), 2);
        for message in messages {
            assert_eq!(
                message
                    .sources
                    .frames()
                    .iter()
                    .map(|frame| frame.number)
                    .collect::<Vec<_>>(),
                [9]
            );
        }
    }

    #[test]
    fn subset_delivery_merges_without_allocating() {
        let tracker = Tracker::new(1 << 20, 8).expect("tracker");
        let flow = flow();
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        let mut output = Vec::new();

        collector
            .data(delivery(&tracker, &flow, 4, b"GET /x"), &mut output)
            .expect("first bytes");
        collector
            .data(delivery(&tracker, &flow, 5, b" HTTP/1.1"), &mut output)
            .expect("second delivery");
        let baseline = tracker.union_reservations();
        // The third delivery contributes only a frame the message already
        // holds, so the one permitted merge is allocation-free.
        collector
            .data(delivery(&tracker, &flow, 5, b"\r\n\r\n"), &mut output)
            .expect("subset delivery");

        assert_eq!(tracker.union_reservations(), baseline);
        let messages = messages(&output);
        let [message] = messages.as_slice() else {
            panic!("one complete message expected, got {}", messages.len());
        };
        assert_eq!(
            message
                .sources
                .frames()
                .iter()
                .map(|frame| frame.number)
                .collect::<Vec<_>>(),
            [4, 5]
        );
    }

    #[test]
    fn bare_cr_and_lf_flush_at_the_offending_byte() {
        // Interior CR not followed by LF.
        let tracker = Tracker::new(1 << 20, 8).expect("tracker");
        let flow = flow();
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        let mut output = Vec::new();
        collector
            .data(
                delivery(&tracker, &flow, 4, b"GET /a HTTP/1.1\rX\r\n\r\n"),
                &mut output,
            )
            .expect("bare CR");
        let bare_cr = messages(&output);
        let [message] = bare_cr.as_slice() else {
            panic!("one malformed message expected, got {}", bare_cr.len());
        };
        assert_eq!(message.status, Status::Malformed);
        assert_eq!(message.header_wire.as_ref(), b"GET /a HTTP/1.1\rX");
        assert!(matches!(
            message.error,
            Some(http::Error::Invalid("header uses a bare CR or LF"))
        ));

        // Interior LF not preceded by CR.
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        output.clear();
        collector
            .data(
                delivery(&tracker, &flow, 5, b"GET /b HTTP/1.1\nrest\r\n\r\n"),
                &mut output,
            )
            .expect("bare LF");
        let bare_lf = messages(&output);
        let [message] = bare_lf.as_slice() else {
            panic!("one malformed message expected, got {}", bare_lf.len());
        };
        assert_eq!(message.status, Status::Malformed);
        assert_eq!(message.header_wire.as_ref(), b"GET /b HTTP/1.1\n");
        assert!(matches!(
            message.error,
            Some(http::Error::Invalid("header uses a bare CR or LF"))
        ));
    }

    #[test]
    fn cr_pending_across_deliveries_pairs_with_lf_or_fails() {
        let tracker = Tracker::new(1 << 20, 8).expect("tracker");
        let flow = flow();
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        let mut output = Vec::new();

        collector
            .data(
                delivery(&tracker, &flow, 4, b"GET /c HTTP/1.1\r"),
                &mut output,
            )
            .expect("pending CR");
        collector
            .data(delivery(&tracker, &flow, 5, b"X: y\r\n\r\n"), &mut output)
            .expect("bare CR at boundary");
        let boundary = messages(&output);
        let [message] = boundary.as_slice() else {
            panic!("one malformed message expected, got {}", boundary.len());
        };
        assert_eq!(message.status, Status::Malformed);
        assert_eq!(message.header_wire.as_ref(), b"GET /c HTTP/1.1\rX");

        // The same boundary completes cleanly when the next byte is LF.
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        output.clear();
        collector
            .data(
                delivery(&tracker, &flow, 6, b"GET /d HTTP/1.1\r"),
                &mut output,
            )
            .expect("pending CR");
        collector
            .data(
                delivery(&tracker, &flow, 7, b"\nHost: h\r\n\r\n"),
                &mut output,
            )
            .expect("CRLF split");
        let completed = messages(&output);
        let [message] = completed.as_slice() else {
            panic!("one complete message expected, got {}", completed.len());
        };
        assert_eq!(message.status, Status::Complete);
        assert_eq!(
            message.header_wire.as_ref(),
            b"GET /d HTTP/1.1\r\nHost: h\r\n\r\n"
        );
    }

    #[test]
    fn header_cap_flushes_the_first_byte_past_the_limit() {
        let tracker = Tracker::new(1 << 20, 8).expect("tracker");
        let flow = flow();
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        let mut output = Vec::new();
        let input: &'static [u8] =
            Box::leak(vec![b'a'; http::MAX_HEADER_BYTES + 2].into_boxed_slice());

        collector
            .data(delivery(&tracker, &flow, 4, input), &mut output)
            .expect("oversized header");

        let messages = messages(&output);
        let [message] = messages.as_slice() else {
            panic!("one limited message expected, got {}", messages.len());
        };
        assert_eq!(message.status, Status::Limit);
        assert_eq!(message.header_wire.len(), http::MAX_HEADER_BYTES + 1);
        assert!(matches!(
            message.error,
            Some(http::Error::Limit("header bytes"))
        ));
    }

    #[test]
    fn delivery_without_consumed_bytes_merges_nothing() {
        let tracker = Tracker::new(1 << 20, 8).expect("tracker");
        let flow = flow();
        let mut collector =
            Collector::new(Limits::default(), vec![80], 1 << 20).expect("collector");
        let mut output = Vec::new();

        collector
            .data(delivery(&tracker, &flow, 4, b"GET /x"), &mut output)
            .expect("first bytes");
        let baseline = tracker.union_reservations();
        collector
            .data(delivery(&tracker, &flow, 5, b""), &mut output)
            .expect("empty delivery");
        assert_eq!(tracker.union_reservations(), baseline);
    }
}
