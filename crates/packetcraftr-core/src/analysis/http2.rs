// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sourced cleartext HTTP/2 and h2c analysis over reassembled TCP.

mod buffer;
mod connection;
mod headers;
mod limits;
mod model;
mod settings;
mod stream;
mod upgrade;

mod error;

pub use error::Error;
pub use limits::{
    Limits, MAX_ACTIVE_STREAMS, MAX_BODY_BYTES, MAX_CONTINUATIONS, MAX_FRAME_BYTES, MAX_FRAMES,
    MAX_HEADER_BLOCK_BYTES, MAX_HEADER_BYTES, MAX_HEADERS, MAX_PENDING_SETTINGS, MAX_STREAMS,
    MAX_TABLE_BYTES,
};
pub use model::{
    Certainty, Connection, Event, Frame, Header, Issue, IssueScope, Message, MessageKind,
    PeerSettings, Startup, Status, Summary,
};

use crate::budget::Deadline;
use crate::error::BoundaryError;
use connection::{ConnectionState, Context, Phase};
use std::collections::BTreeMap;
use std::sync::Arc;

use super::{
    FrameRecord, Summary as RunSummary,
    application::{self, TcpSources},
    reassembly::tcp::ScopedFlowKey,
    scope::Definition,
    session::{self, CollectorNeeds},
};

type ConnectionKey = (u64, u64);

pub struct Collector {
    app_limits: application::Limits,
    limits: Limits,
    deadline: Option<Arc<Deadline>>,
    tcp: TcpSources,
    // Boxed so each delivery moves a pointer rather than the whole connection.
    connections: BTreeMap<ConnectionKey, Box<ConnectionState>>,
    flow_index: BTreeMap<ScopedFlowKey, ConnectionKey>,
    buffered: usize,
    retained: usize,
    spans: usize,
    frames: u64,
    streams: u64,
    messages: u64,
    summary: Summary,
    failed: bool,
}

impl Collector {
    pub fn new(
        application: application::Limits,
        ports: impl IntoIterator<Item = u16>,
        limits: Limits,
    ) -> Result<Self, Error> {
        application.validate()?;
        let ports = application::normalize_ports(ports, "http2_ports")?;
        limits.validate()?;
        Ok(Self {
            app_limits: application,
            limits,
            deadline: None,
            tcp: TcpSources::new(ports, application),
            connections: BTreeMap::new(),
            flow_index: BTreeMap::new(),
            buffered: 0,
            retained: 0,
            spans: 0,
            frames: 0,
            streams: 0,
            messages: 0,
            summary: Summary::default(),
            failed: false,
        })
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Arc<Deadline>) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn scopes(&self) -> impl Iterator<Item = &Definition> {
        self.tcp.scopes.values()
    }

    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Event>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let mut out = Vec::new();
        if let Err(error) = self.observe_into(record, &mut out) {
            self.failed = true;
            self.connections.clear();
            self.flow_index.clear();
            return Err(error);
        }
        Ok(out)
    }

    fn observe_into(
        &mut self,
        record: &FrameRecord<'_>,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if let Some(deadline) = self.deadline.as_deref() {
            deadline.enforce()?;
        }
        for event in self.tcp.observe(record)? {
            self.dispatch(event, record.number, out)?;
        }
        Ok(())
    }

    fn with_context<'a>(&'a mut self, out: &'a mut Vec<Event>) -> Context<'a> {
        Context {
            limits: &self.limits,
            app: &self.app_limits,
            deadline: self.deadline.as_deref(),
            buffered: &mut self.buffered,
            retained: &mut self.retained,
            spans: &mut self.spans,
            frames: &mut self.frames,
            streams: &mut self.streams,
            messages: &mut self.messages,
            summary: &mut self.summary,
            out,
        }
    }

    fn dispatch(
        &mut self,
        event: application::Event,
        number: u64,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        match event {
            application::Event::Data(delivery) => {
                let key = (delivery.stream, delivery.generation);
                if let Some(&old) = self.flow_index.get(&delivery.flow)
                    && old != key
                    && let Some(mut conn) = self.connections.remove(&old)
                {
                    self.flow_index.retain(|_, k| *k != old);
                    conn.number = number;
                    if !conn.done && !matches!(conn.phase, Phase::Dead) {
                        conn.terminate(
                            &delivery.flow,
                            Status::Evicted,
                            "generation_replaced",
                            "the TCP tuple was reused for a newer connection",
                            &mut self.with_context(out),
                        )?;
                    }
                    conn.finish(&mut self.with_context(out))?;
                }
                let mut conn = self.connections.remove(&key).unwrap_or_else(|| {
                    Box::new(ConnectionState::new(
                        delivery.stream,
                        delivery.generation,
                        delivery.flow.clone(),
                    ))
                });
                if self.flow_index.get(&delivery.flow) != Some(&key) {
                    self.flow_index.insert(delivery.flow.clone(), key);
                }
                let result = conn.data(&delivery, number, &mut self.with_context(out));
                self.connections.insert(key, conn);
                result
            }
            application::Event::Gap { flow, .. } => self.fail_flow(
                &flow,
                number,
                Status::Gap,
                "tcp_gap",
                "a TCP sequence gap invalidated the byte stream",
                out,
            ),
            application::Event::Conflict { flow, .. } => self.fail_flow(
                &flow,
                number,
                Status::Conflict,
                "tcp_conflict",
                "conflicting TCP retransmissions invalidated the byte stream",
                out,
            ),
            application::Event::Evicted { flow, .. } => self.fail_flow(
                &flow,
                number,
                Status::Evicted,
                "tcp_evicted",
                "reassembly state was evicted before the stream completed",
                out,
            ),
            application::Event::Closed { flow, reset, .. } => {
                let Some(key) = self
                    .flow_index
                    .get(&flow)
                    .or_else(|| self.flow_index.get(&flow.reverse()))
                    .copied()
                else {
                    return Ok(());
                };
                let Some(mut conn) = self.connections.remove(&key) else {
                    return Ok(());
                };
                if !conn.has_flow(&flow) && !conn.has_flow(&flow.reverse()) {
                    self.connections.insert(key, conn);
                    return Ok(());
                }
                conn.number = number;
                let result = conn.close(&flow, reset, &mut self.with_context(out));
                self.connections.insert(key, conn);
                result
            }
        }
    }

    fn fail_flow(
        &mut self,
        flow: &ScopedFlowKey,
        number: u64,
        status: Status,
        code: &'static str,
        detail: &'static str,
        out: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let keys: Vec<ConnectionKey> = self
            .flow_index
            .iter()
            .filter(|(f, _)| *f == flow || f.reverse() == *flow)
            .map(|(_, key)| *key)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        for key in keys {
            if let Some(mut conn) = self.connections.remove(&key) {
                conn.number = number;
                conn.terminate(flow, status, code, detail, &mut self.with_context(out))?;
                self.connections.insert(key, conn);
            }
        }
        Ok(())
    }

    pub fn finish(self, run: &RunSummary) -> Result<(Vec<Event>, Summary), Error> {
        let mut out = Vec::new();
        let summary = self.finalize(run, |events| {
            out.extend(events);
            Ok(())
        })?;
        Ok((out, summary))
    }

    fn finalize(
        mut self,
        run: &RunSummary,
        mut emit: impl FnMut(Vec<Event>) -> Result<(), Error>,
    ) -> Result<Summary, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if let Some(deadline) = self.deadline.as_deref() {
            deadline.enforce()?;
        }
        for event in self
            .tcp
            .trailing(&run.trailing_tcp_events, run.frames_read)?
        {
            if let Some(deadline) = self.deadline.as_deref() {
                deadline.enforce()?;
            }
            let mut out = Vec::new();
            if !matches!(event, application::Event::Evicted { .. }) {
                self.dispatch(event, run.frames_read, &mut out)?;
            }
            emit(out)?;
        }
        for mut conn in std::mem::take(&mut self.connections).into_values() {
            if let Some(deadline) = self.deadline.as_deref() {
                deadline.enforce()?;
            }
            let mut out = Vec::new();
            conn.number = run.frames_read;
            conn.finish(&mut self.with_context(&mut out))?;
            emit(out)?;
        }
        if let Some(deadline) = self.deadline.as_deref() {
            deadline.enforce()?;
        }
        Ok(self.summary)
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
        mut self,
        run: &RunSummary,
        deadline: &Deadline,
        event_sink: &mut dyn FnMut(Event) -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        self.deadline = Some(Arc::new(deadline.clone().with_parent(self.deadline.take())));
        self.finalize(run, |events| {
            session::deliver(deadline, events, event_sink).map_err(Error::Output)
        })
        .map_err(BoundaryError::from_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{self, Session, provenance::SourceSet},
        build::Builder,
        capture_file::{Format, Reader, Writer},
        error::Classified,
        frame::{Frame as CaptureFrame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, network::Ipv4, transport::Tcp},
        registry::Registry,
    };
    use bytes::Bytes;
    use std::{
        io::Cursor,
        net::{Ipv4Addr, SocketAddrV4},
        time::{Duration, Instant, UNIX_EPOCH},
    };

    // Prior knowledge, frame headers and stream flags, checked 2026-10-25.
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-3.4
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-4.1
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    // HPACK size update, static indices and literal fields, checked 2026-10-25.
    // https://www.rfc-editor.org/rfc/rfc7541.html#section-6
    // https://www.rfc-editor.org/rfc/rfc7541.html#appendix-A
    const REQUEST_BLOCK: &[u8] = b"\x20\x82\x86\x84\x01\x09unit.test";
    const RESPONSE_BLOCK: &[u8] = &[0x20, 0x88, 0x0f, 0x0d, 0x01, b'3'];

    #[derive(Clone, Copy)]
    enum Lifecycle {
        Session,
        Direct,
    }

    fn registry() -> Arc<Registry> {
        Arc::new(
            builtin::registry_with(|builder| {
                builder.bind("tcp", 40000, "raw", i32::MAX)?;
                builder.bind("tcp", 8082, "raw", i32::MAX)?;
                Ok(())
            })
            .unwrap(),
        )
    }

    fn endpoints(response: bool) -> (SocketAddrV4, SocketAddrV4) {
        let client = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 40000);
        let server = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 81), 8082);
        if response {
            (server, client)
        } else {
            (client, server)
        }
    }

    fn tcp_frame(number: u64, response: bool, mut header: Tcp, payload: &[u8]) -> CaptureFrame {
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
        CaptureFrame::new(
            UNIX_EPOCH + Duration::from_secs(100 + number),
            LinkType::RAW,
            built.bytes,
        )
        .unwrap()
    }

    fn wire_frame(frame_type: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
        [
            &length[1..],
            &[frame_type, flags],
            &stream.to_be_bytes(),
            payload,
        ]
        .concat()
    }

    fn capture() -> Vec<CaptureFrame> {
        let client_settings = wire_frame(4, 0, 0, &[0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 8, 0]);
        let server_settings = wire_frame(4, 0, 0, &[0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 16, 0]);
        let ack = wire_frame(4, 1, 0, &[]);
        let request = wire_frame(1, 5, 7, REQUEST_BLOCK);
        let response = wire_frame(1, 4, 7, RESPONSE_BLOCK);
        let data = wire_frame(0, 1, 7, b"abc");
        let client_start = [PREFACE, client_settings.as_slice()].concat();
        let server_start = [server_settings.as_slice(), ack.as_slice()].concat();
        let client_request = [ack.as_slice(), request.as_slice()].concat();
        let mut frames = vec![
            tcp_frame(
                1,
                false,
                Tcp {
                    sequence: 100,
                    flags: Tcp::SYN,
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
                    ..Default::default()
                },
                &[],
            ),
        ];
        let mut sequences = [101, 901];
        for (server, bytes) in [
            (false, client_start.as_slice()),
            (true, server_start.as_slice()),
            (false, client_request.as_slice()),
            (true, response.as_slice()),
            (true, data.as_slice()),
        ] {
            let side = usize::from(server);
            frames.push(tcp_frame(
                frames.len() as u64 + 1,
                server,
                Tcp {
                    sequence: sequences[side],
                    acknowledgment: sequences[1 - side],
                    flags: Tcp::ACK,
                    ..Default::default()
                },
                bytes,
            ));
            sequences[side] += u32::try_from(bytes.len()).unwrap();
        }
        for server in [false, true] {
            let side = usize::from(server);
            frames.push(tcp_frame(
                frames.len() as u64 + 1,
                server,
                Tcp {
                    sequence: sequences[side],
                    acknowledgment: sequences[1 - side],
                    flags: Tcp::FIN | Tcp::ACK,
                    ..Default::default()
                },
                &[],
            ));
            sequences[side] += 1;
        }
        frames.push(tcp_frame(
            frames.len() as u64 + 1,
            false,
            Tcp {
                sequence: sequences[0],
                acknowledgment: sequences[1],
                flags: Tcp::ACK,
                ..Default::default()
            },
            &[],
        ));
        frames
    }

    fn collect(
        frames: &[CaptureFrame],
        lifecycle: Lifecycle,
        max_frames: u64,
    ) -> Result<(Vec<Event>, Summary, Vec<Definition>), analysis::Error> {
        let mut writer = Writer::new(Vec::new(), Format::Pcap, LinkType::RAW).unwrap();
        for frame in frames {
            writer.write_frame(frame).unwrap();
        }
        let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
        let now = Instant::now();
        let deadline = Arc::new(Deadline::with_time_source(
            Duration::from_secs(30),
            move || now,
        ));
        let collector = Collector::new(
            application::Limits {
                max_messages: 8,
                max_streams: 4,
                max_buffer_bytes: 64 * 1024,
                max_retained_bytes: 256 * 1024,
                max_source_spans: 128,
            },
            [8082],
            Limits {
                max_frames,
                max_streams: 4,
                max_active_streams: 4,
                max_frame_bytes: 1024,
                max_header_block_bytes: 256,
                max_header_bytes: 1024,
                max_headers: 16,
                max_table_bytes: 8192,
                max_continuations: 4,
                max_pending_settings: 4,
                max_body_bytes: 64,
            },
        )
        .unwrap()
        .with_deadline(Arc::clone(&deadline));
        let options = analysis::Options {
            deadline: Some(deadline),
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

    fn source_numbers(set: &SourceSet) -> Vec<u64> {
        set.iter().map(|source| source.number).collect()
    }

    fn header<'a>(message: &'a Message, name: &[u8]) -> &'a [u8] {
        message
            .headers
            .iter()
            .find(|field| field.name.as_ref() == name)
            .unwrap()
            .value
            .as_ref()
    }

    fn flow(message: &Message, response: bool) {
        let (source, destination) = endpoints(response);
        assert_eq!(message.flow.flow.source, *source.ip());
        assert_eq!(message.flow.flow.destination, *destination.ip());
        assert_eq!(message.flow.flow.source_port, source.port());
        assert_eq!(message.flow.flow.destination_port, destination.port());
    }

    #[test]
    fn prior_knowledge_capture_preserves_settings_headers_data_and_frame_admission() {
        let capture = capture();
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (events, summary, scopes) = collect(&capture, lifecycle, 7).unwrap();
            let messages = events
                .iter()
                .filter_map(|event| match event {
                    Event::Message(message) => Some(message.as_ref()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [request, response] = messages.as_slice() else {
                panic!("expected the supplied request and completed response")
            };
            assert_eq!(request.kind, MessageKind::Request);
            assert_eq!(request.status, Status::Complete);
            assert_eq!(request.http2_stream_id, 7);
            assert_eq!(request.body_bytes, 0);
            assert_eq!(header(request, b":method"), b"GET");
            assert_eq!(header(request, b":scheme"), b"http");
            assert_eq!(header(request, b":path"), b"/");
            assert_eq!(header(request, b":authority"), b"unit.test");
            assert_eq!(
                request
                    .header_blocks
                    .iter()
                    .map(Bytes::as_ref)
                    .collect::<Vec<_>>(),
                [REQUEST_BLOCK]
            );
            assert_eq!(source_numbers(&request.sources), [6]);
            flow(request, false);
            assert_eq!(response.kind, MessageKind::Response);
            assert_eq!(response.status, Status::Complete);
            assert_eq!(response.http2_stream_id, 7);
            assert_eq!(response.request, Some(request.index));
            assert_eq!(response.body_bytes, 3);
            assert_eq!(header(response, b":status"), b"200");
            assert_eq!(header(response, b"content-length"), b"3");
            assert_eq!(
                response
                    .header_blocks
                    .iter()
                    .map(Bytes::as_ref)
                    .collect::<Vec<_>>(),
                [RESPONSE_BLOCK]
            );
            assert_eq!(source_numbers(&response.sources), [7, 8]);
            flow(response, true);
            for message in &messages {
                assert!(scopes.iter().any(|scope| scope.id == message.flow.scope));
            }
            let frames = events
                .iter()
                .filter_map(|event| match event {
                    Event::Frame(frame) => Some(frame.as_ref()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                frames
                    .iter()
                    .map(|frame| (
                        frame.header.frame_type,
                        frame.header.flags,
                        frame.header.stream_id,
                        frame.header.length
                    ))
                    .collect::<Vec<_>>(),
                [
                    (4, 0, 0, 12),
                    (4, 0, 0, 12),
                    (4, 1, 0, 0),
                    (4, 1, 0, 0),
                    (1, 5, 7, u32::try_from(REQUEST_BLOCK.len()).unwrap()),
                    (1, 4, 7, u32::try_from(RESPONSE_BLOCK.len()).unwrap()),
                    (0, 1, 7, 3),
                ]
            );
            assert_eq!(frames.last().unwrap().data_bytes, 3);
            assert_eq!(source_numbers(&frames.last().unwrap().sources), [8]);
            let connections = events
                .iter()
                .filter_map(|event| match event {
                    Event::Connection(connection) => Some(connection.as_ref()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [connection] = connections.as_slice() else {
                panic!("expected finalized connection metadata")
            };
            assert_eq!(connection.startup, Startup::PriorKnowledge);
            assert_eq!(connection.status, Status::Complete);
            assert_eq!(connection.client_settings.header_table_size, 0);
            assert_eq!(connection.server_settings.header_table_size, 0);
            assert_eq!(connection.client_settings.initial_window_size, 2048);
            assert_eq!(connection.server_settings.initial_window_size, 4096);
            assert_eq!(
                (
                    connection.frames,
                    connection.streams,
                    connection.pending_settings
                ),
                (7, 1, 0)
            );
            assert_eq!(
                (
                    summary.connections,
                    summary.prior_knowledge_connections,
                    summary.frames,
                    summary.streams,
                    summary.messages,
                    summary.complete_messages,
                    summary.issues
                ),
                (1, 1, 7, 1, 2, 2, 0)
            );
            let error = collect(&capture, lifecycle, 6).unwrap_err();
            assert_eq!(error.classification().code, "policy.application_limit");
            assert!(
                error
                    .causes()
                    .iter()
                    .any(|cause| cause.contains("max_frames=6"))
            );
        }
    }
}
