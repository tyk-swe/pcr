// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod transactions;

use super::{
    FrameRecord, StreamTransport, Summary as RunSummary,
    application::{self, Error, Limits, TcpSources},
    provenance::{Accumulator, SourceSet},
    reassembly::tcp::ScopedFlowKey,
    scope::Definition,
    session::{self, CollectorNeeds},
};
use crate::{
    error::BoundaryError,
    field::WireValue,
    protocol::{
        application::dns::{self, Dns},
        transport::Udp,
    },
};
use bytes::Bytes;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
pub use transactions::{Latency, Transaction, TransactionStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Malformed,
    Incomplete,
    Gap,
    Conflict,
    Reset,
    Evicted,
}
#[derive(Clone, Debug)]
pub struct Message {
    pub index: u64,
    pub transport: StreamTransport,
    pub stream: u64,
    pub generation: u64,
    pub flow: ScopedFlowKey,
    pub status: Status,
    /// Complete DNS wire or the captured part, excluding the TCP length prefix.
    pub wire: Bytes,
    pub declared_length: Option<u16>,
    pub framing_bytes: Bytes,
    pub dns: Option<Dns>,
    pub error: Option<dns::Error>,
    pub sources: SourceSet,
}
#[derive(Clone, Debug)]
pub enum Event {
    Issue(StreamIssue),
    Message(Box<Message>),
    Transaction(Transaction),
}
#[derive(Clone, Debug, Serialize)]
pub struct StreamIssue {
    pub number: u64,
    pub flow: ScopedFlowKey,
    pub stream: u64,
    pub status: Status,
}
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
    sources: Option<Accumulator>,
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
/// Feed it unfiltered records with TCP events and physical-source tracking
/// enabled.
pub struct Collector {
    limits: Limits,
    ports: Vec<u16>,
    seen_streams: BTreeSet<(StreamTransport, u64)>,
    tcp: TcpSources,
    directions: BTreeMap<ScopedFlowKey, Direction>,
    scopes: BTreeMap<u32, Definition>,
    buffered: usize,
    retained: usize,
    transactions: transactions::Tracker,
    summary: Summary,
}
impl Collector {
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
            retained: 0,
            transactions: transactions::Tracker::new(limits),
            summary: Summary::default(),
        })
    }
    fn register_stream(&mut self, transport: StreamTransport, stream: u64) -> Result<(), Error> {
        if !self.seen_streams.contains(&(transport, stream)) {
            self.limits.check_streams(self.seen_streams.len())?;
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
                self.register_stream(StreamTransport::Udp, conversation.index)?;
                if let Some(scope) = record.scope_definition(flow.scope) {
                    self.scopes
                        .entry(scope.id.get())
                        .or_insert_with(|| scope.clone());
                }
                let header = view
                    .decoded
                    .packet
                    .layer(view.layer)
                    .and_then(|layer| layer.downcast_ref::<Udp>())
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
                    .min(view.decoded.frame.bytes().len());
                // The emitted wire and every decoded name/rdata slice derived
                // from it must own their bytes; slicing the record would pin
                // the entire frame allocation behind a few DNS bytes.
                let start = start.min(end);
                let wire = Bytes::copy_from_slice(&view.decoded.frame.bytes()[start..end]);
                let sources = record
                    .udp_sources()
                    .ok_or(Error::Sources {
                        number: record.number,
                    })?
                    .clone();
                self.emit(
                    Message {
                        index: 0,
                        transport: StreamTransport::Udp,
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
            self.register_stream(StreamTransport::Tcp, conversation.index)?;
        }
        for event in self.tcp.observe(record)? {
            self.tcp_event(event, record.number, &mut events)?;
        }
        Ok(events)
    }
    pub fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
        let mut events = Vec::new();
        let summary = self.finalize(
            run,
            || Ok(()),
            |batch| {
                events.extend(batch);
                Ok(())
            },
        )?;
        Ok((events, summary))
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
            let mut events = Vec::new();
            if let application::Event::Evicted { flow, .. } = event {
                self.stop(flow, Status::Incomplete, &mut events)?;
            } else {
                self.tcp_event(event, run.frames_read, &mut events)?;
            }
            emit(events)?;
        }
        for (flow, mut direction) in std::mem::take(&mut self.directions) {
            check()?;
            let mut events = Vec::new();
            self.flush(&flow, &mut direction, Status::Incomplete, &mut events)?;
            emit(events)?;
        }
        for transaction in self.transactions.finish(&mut check)? {
            check()?;
            let mut events = Vec::new();
            self.transaction(transaction, &mut events);
            emit(events)?;
        }
        check()?;
        Ok(self.summary)
    }
    fn tcp_event(
        &mut self,
        event: application::Event,
        number: u64,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let issue = match &event {
            application::Event::Gap { flow, stream, .. } => Some((flow, stream, Status::Gap)),
            application::Event::Conflict { flow, stream, .. } => {
                Some((flow, stream, Status::Conflict))
            }
            application::Event::Evicted { flow, stream, .. } => {
                Some((flow, stream, Status::Evicted))
            }
            application::Event::Closed {
                flow,
                stream,
                reset: true,
                ..
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
                    self.limits
                        .check_buffer(self.buffered.saturating_add(take))?;
                    if let Some(sources) = direction.sources.as_mut() {
                        sources.insert(&data.sources)?;
                    } else {
                        direction.sources = Some(Accumulator::new(&data.sources)?);
                    }
                    self.limits.check_source_spans(
                        direction
                            .sources
                            .as_ref()
                            .expect("initialized sources")
                            .len(),
                    )?;
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
            application::Event::Gap { flow, .. } => {
                self.stop(flow, Status::Gap, events)?;
            }
            application::Event::Conflict { flow, .. } => {
                self.stop(flow, Status::Conflict, events)?;
            }
            application::Event::Evicted { flow, .. } => {
                self.stop(flow, Status::Evicted, events)?;
            }
            application::Event::Closed { flow, reset, .. } => {
                self.stop(
                    flow.clone(),
                    if reset {
                        Status::Reset
                    } else {
                        Status::Incomplete
                    },
                    events,
                )?;
                if reset {
                    self.stop(flow.reverse(), Status::Reset, events)?;
                }
            }
        }
        Ok(())
    }
    fn stop(
        &mut self,
        flow: ScopedFlowKey,
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
                transport: StreamTransport::Tcp,
                stream: direction.stream,
                generation: direction.generation,
                flow: flow.clone(),
                status,
                wire,
                declared_length,
                framing_bytes,
                dns: None,
                error: None,
                sources: sources.freeze()?,
            },
            events,
        )
    }
    fn emit(&mut self, mut message: Message, events: &mut Vec<Event>) -> Result<(), Error> {
        self.limits.check_messages(self.summary.messages as usize)?;
        self.retained = self
            .retained
            .saturating_add(Limits::decoded_charge(message.wire.len()));
        self.limits.check_retained(self.retained)?;
        self.summary.messages += 1;
        message.index = self.summary.messages;
        if message.status == Status::Complete {
            match Dns::from_wire_with_limits(message.wire.clone(), dns::Limits::default()) {
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
        let transactions = self.transactions.observe(&message, &mut self.retained)?;
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

impl session::Collector for Collector {
    type Event = Event;
    type Summary = Summary;

    fn needs(&self) -> CollectorNeeds {
        CollectorNeeds {
            tcp_stream: true,
            udp_stream: true,
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
mod tests {
    use super::*;
    use crate::{
        analysis::{self, Session},
        budget::Deadline,
        build::Builder,
        capture_file::{Format, Reader, Writer},
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{application::dns::RecordValue, builtin, network::Ipv4, transport::Tcp},
        registry::Registry,
    };
    use std::{
        io::Cursor,
        net::{Ipv4Addr, SocketAddrV4},
        sync::Arc,
        time::{Duration, Instant, UNIX_EPOCH},
    };

    // DNS header, question, resource record and compression fields, checked 2026-10-25.
    // https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1
    const QUERY: &[u8] =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01";
    const ANSWER: &[u8] =
        b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x09";

    #[derive(Clone, Copy)]
    enum Lifecycle {
        Session,
        Direct,
    }

    fn registry() -> Arc<Registry> {
        Arc::new(
            builtin::registry_with(|builder| {
                for (protocol, port) in
                    [("udp", 40000), ("udp", 5354), ("tcp", 40000), ("tcp", 5354)]
                {
                    builder.bind(protocol, port, "raw", i32::MAX)?;
                }
                Ok(())
            })
            .unwrap(),
        )
    }

    fn endpoints(response: bool) -> (SocketAddrV4, SocketAddrV4) {
        let client = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40000);
        let server = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 53), 5354);
        if response {
            (server, client)
        } else {
            (client, server)
        }
    }

    fn base_packet(response: bool) -> Packet {
        let (source, destination) = endpoints(response);
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: *source.ip(),
            destination: *destination.ip(),
            ..Default::default()
        });
        packet
    }

    fn frame(number: u64, packet: Packet) -> Frame {
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

    fn udp_frame(number: u64, response: bool, wire: &[u8]) -> Frame {
        let (source, destination) = endpoints(response);
        let mut packet = base_packet(response);
        packet.push(Udp {
            source_port: source.port(),
            destination_port: destination.port(),
            ..Default::default()
        });
        packet.push(Raw::new(wire.to_vec()));
        frame(number, packet)
    }

    fn tcp_frame(number: u64, response: bool, mut header: Tcp, payload: &[u8]) -> Frame {
        let (source, destination) = endpoints(response);
        header.source_port = source.port();
        header.destination_port = destination.port();
        let mut packet = base_packet(response);
        packet.push(header);
        if !payload.is_empty() {
            packet.push(Raw::new(payload.to_vec()));
        }
        frame(number, packet)
    }

    fn options(lifecycle: Lifecycle) -> analysis::Options<'static> {
        let now = Instant::now();
        analysis::Options {
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
        }
    }

    fn collect(frames: &[Frame], lifecycle: Lifecycle) -> (Vec<Event>, Summary, Vec<Definition>) {
        let mut writer = Writer::new(Vec::new(), Format::Pcap, LinkType::RAW).unwrap();
        for frame in frames {
            writer.write_frame(frame).unwrap();
        }
        let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
        let collector = Collector::new(
            Limits {
                max_messages: 16,
                max_streams: 4,
                max_buffer_bytes: QUERY.len() + 2,
                max_retained_bytes: 128 * 1024,
                max_source_spans: 16,
            },
            [5354],
        )
        .unwrap();
        let mut events = Vec::new();
        match lifecycle {
            Lifecycle::Session => {
                let outcome = Session::new(registry(), options(lifecycle), collector)
                    .run(
                        &mut reader,
                        |_| Ok(()),
                        |event| {
                            events.push(event);
                            Ok(())
                        },
                    )
                    .unwrap();
                (events, outcome.summary, outcome.scopes)
            }
            Lifecycle::Direct => {
                let mut collector = collector;
                let run = analysis::run(&mut reader, registry(), &options(lifecycle), |record| {
                    events.extend(<Collector as analysis::Collector>::observe(
                        &mut collector,
                        &record,
                    )?);
                    Ok(())
                })
                .unwrap();
                let scopes = <Collector as analysis::Collector>::scopes(&collector);
                let (tail, summary) =
                    <Collector as analysis::Collector>::finish(collector, &run).unwrap();
                events.extend(tail);
                (events, summary, scopes)
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

    fn transactions(events: &[Event]) -> Vec<&Transaction> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Transaction(transaction) => Some(transaction),
                _ => None,
            })
            .collect()
    }

    fn sources(set: &SourceSet) -> Vec<u64> {
        set.iter().map(|source| source.number).collect()
    }

    fn complete<'a>(
        message: &'a Message,
        transport: StreamTransport,
        wire: &[u8],
        id: u16,
        response: bool,
        frames: &[u64],
    ) -> &'a Dns {
        assert_eq!(message.status, Status::Complete);
        assert_eq!(message.transport, transport);
        assert_eq!(message.wire.as_ref(), wire);
        assert_eq!(
            message.declared_length,
            Some(u16::try_from(wire.len()).unwrap())
        );
        assert!(message.error.is_none());
        assert_eq!(sources(&message.sources), frames);
        let dns = message.dns.as_ref().unwrap();
        assert_eq!(dns.id, id);
        assert_eq!(dns.response, response);
        assert_eq!(dns.rcode, 0);
        let [question] = dns.questions.as_slice() else {
            panic!("expected the supplied DNS question")
        };
        let labels: Vec<&[u8]> = question.name.labels().iter().map(Bytes::as_ref).collect();
        assert_eq!(labels, [b"example".as_slice(), b"test".as_slice()]);
        assert_eq!((question.query_type, question.class), (1, 1));
        dns
    }

    fn client_flow(flow: &ScopedFlowKey) {
        let (client, server) = endpoints(false);
        assert_eq!(flow.flow.source, *client.ip());
        assert_eq!(flow.flow.destination, *server.ip());
        assert_eq!(flow.flow.source_port, client.port());
        assert_eq!(flow.flow.destination_port, server.port());
    }

    #[test]
    fn udp_capture_publishes_decoded_messages_matched_and_orphan_transactions() {
        let mut orphan = ANSWER.to_vec();
        orphan[..2].copy_from_slice(&[0xbe, 0xef]);
        *orphan.last_mut().unwrap() = 17;
        let frames = [
            udp_frame(1, false, QUERY),
            udp_frame(2, true, ANSWER),
            udp_frame(3, true, &orphan),
        ];
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (events, summary, scopes) = collect(&frames, lifecycle);
            let messages = messages(&events);
            let [query, answer, orphan_response] = messages.as_slice() else {
                panic!("expected the query, answer and independent orphan response")
            };
            complete(query, StreamTransport::Udp, QUERY, 0x1234, false, &[1]);
            let answer_dns = complete(answer, StreamTransport::Udp, ANSWER, 0x1234, true, &[2]);
            let orphan_dns = complete(
                orphan_response,
                StreamTransport::Udp,
                &orphan,
                0xbeef,
                true,
                &[3],
            );
            for (dns, address) in [(answer_dns, [192, 0, 2, 9]), (orphan_dns, [192, 0, 2, 17])] {
                let [record] = dns.answers.as_slice() else {
                    panic!("expected the supplied A answer")
                };
                assert_eq!(record.ttl, 60);
                assert_eq!(record.value, RecordValue::A(address.into()));
            }
            assert!(query.index < answer.index && answer.index < orphan_response.index);
            for message in &messages {
                assert!(message.framing_bytes.is_empty());
                assert!(scopes.iter().any(|scope| scope.id == message.flow.scope));
            }
            let transactions = transactions(&events);
            let [matched, orphan] = transactions.as_slice() else {
                panic!("expected the matched query and finalized orphan")
            };
            assert_eq!(matched.status, TransactionStatus::Matched);
            assert_eq!(matched.transport, StreamTransport::Udp);
            assert_eq!(matched.dns_id, 0x1234);
            assert_eq!(matched.queries, [query.index]);
            assert_eq!(matched.response, Some(answer.index));
            assert_eq!(sources(&matched.sources), [1, 2]);
            assert_eq!(
                matched.first_query_latency,
                Some(Latency {
                    nanoseconds: 1_000_000_000,
                    negative: false,
                })
            );
            assert_eq!(matched.latest_query_latency, matched.first_query_latency);
            client_flow(&matched.flow);
            assert_eq!(orphan.status, TransactionStatus::OrphanResponse);
            assert_eq!(orphan.dns_id, 0xbeef);
            assert!(orphan.queries.is_empty());
            assert_eq!(orphan.response, Some(orphan_response.index));
            assert_eq!(sources(&orphan.sources), [3]);
            client_flow(&orphan.flow);
            assert_eq!(
                (
                    summary.messages,
                    summary.complete_messages,
                    summary.transactions,
                    summary.matched_transactions,
                    summary.unanswered_transactions,
                    summary.orphan_responses,
                    summary.duplicate_responses,
                ),
                (3, 3, 2, 1, 0, 1, 0)
            );
        }
    }

    #[test]
    fn tcp_capture_finalizes_split_queries_partial_messages_and_unanswered_sources() {
        // TCP DNS length framing, checked 2026-10-25.
        // https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2.2
        // TCP setup and sequence progression, checked 2026-10-25.
        // https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5
        let partial = [0xbe, 0xef, 0x01, 0x00, 0x00];
        let tail = [&[30][..], QUERY, &[0, 64], &partial].concat();
        let frames = [
            tcp_frame(
                1,
                false,
                Tcp {
                    sequence: 100,
                    flags: Tcp::SYN,
                    window: 4096,
                    ..Default::default()
                },
                &[],
            ),
            tcp_frame(
                2,
                true,
                Tcp {
                    sequence: 900,
                    acknowledgment: 101,
                    flags: Tcp::SYN | Tcp::ACK,
                    window: 4096,
                    ..Default::default()
                },
                &[],
            ),
            tcp_frame(
                3,
                false,
                Tcp {
                    sequence: 101,
                    acknowledgment: 901,
                    flags: Tcp::ACK,
                    window: 4096,
                    ..Default::default()
                },
                &[],
            ),
            tcp_frame(
                4,
                false,
                Tcp {
                    sequence: 101,
                    acknowledgment: 901,
                    flags: Tcp::ACK,
                    window: 4096,
                    ..Default::default()
                },
                &[0],
            ),
            tcp_frame(
                5,
                false,
                Tcp {
                    sequence: 102,
                    acknowledgment: 901,
                    flags: Tcp::ACK,
                    window: 4096,
                    ..Default::default()
                },
                &tail,
            ),
        ];
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (events, summary, scopes) = collect(&frames, lifecycle);
            let messages = messages(&events);
            let [query, incomplete] = messages.as_slice() else {
                panic!("expected a complete split query and its unfinished successor")
            };
            complete(query, StreamTransport::Tcp, QUERY, 0x1234, false, &[4, 5]);
            assert_eq!(query.framing_bytes.as_ref(), &[0, 30]);
            assert_eq!(incomplete.status, Status::Incomplete);
            assert_eq!(incomplete.transport, StreamTransport::Tcp);
            assert_eq!(incomplete.declared_length, Some(64));
            assert_eq!(incomplete.framing_bytes.as_ref(), &[0, 64]);
            assert_eq!(incomplete.wire.as_ref(), &partial);
            assert!(incomplete.dns.is_none());
            assert!(incomplete.error.is_none());
            assert_eq!(sources(&incomplete.sources), [5]);
            for message in &messages {
                assert!(scopes.iter().any(|scope| scope.id == message.flow.scope));
            }
            let transactions = transactions(&events);
            let [unanswered] = transactions.as_slice() else {
                panic!("expected the complete query's unanswered transaction")
            };
            assert_eq!(unanswered.status, TransactionStatus::Unanswered);
            assert_eq!(unanswered.transport, StreamTransport::Tcp);
            assert_eq!(unanswered.dns_id, 0x1234);
            assert_eq!(unanswered.queries, [query.index]);
            assert_eq!(unanswered.response, None);
            assert_eq!(sources(&unanswered.sources), [4, 5]);
            assert_eq!(unanswered.first_query_latency, None);
            assert_eq!(unanswered.latest_query_latency, None);
            client_flow(&unanswered.flow);
            assert_eq!(
                (
                    summary.messages,
                    summary.complete_messages,
                    summary.transactions,
                    summary.matched_transactions,
                    summary.unanswered_transactions,
                    summary.orphan_responses,
                    summary.duplicate_responses,
                ),
                (2, 1, 1, 0, 1, 0, 0)
            );
        }
    }
}
