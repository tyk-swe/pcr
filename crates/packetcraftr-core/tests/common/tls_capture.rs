// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A scripted TCP capture builder for TLS session assembly contracts.

use super::tls_frames::{
    ClientHelloSpec, ServerHelloSpec, client_hello, handshake_record, server_hello, split,
};
use super::{
    CLIENT, SERVER, TcpSpec, client_tcp, reader, registry, server_tcp, tcp_frame, udp_frame,
};
use packetcraftr_core::analysis::tls::{
    Collector, Limits as TlsLimits, Session, Summary as TlsSummary,
};
use packetcraftr_core::analysis::{FrameRecord, Options, run};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// A capture under construction: one clock, any number of conversations.
pub(crate) struct Capture {
    pub(crate) registry: Arc<Registry>,
    pub(crate) tick: u64,
    pub(crate) frames: Vec<Frame>,
}

/// One TCP conversation's sequence bookkeeping.
#[derive(Clone, Copy)]
pub(crate) struct Stream {
    pub(crate) port: u16,
    pub(crate) server_port: u16,
    pub(crate) client_sequence: u32,
    pub(crate) server_sequence: u32,
}

impl Stream {
    pub(crate) fn new(port: u16) -> Self {
        Self {
            port,
            server_port: 443,
            client_sequence: 1_000,
            server_sequence: 5_000,
        }
    }
}

impl Capture {
    pub(crate) fn new() -> Self {
        Self {
            registry: registry(),
            tick: 0,
            frames: Vec::new(),
        }
    }

    pub(crate) fn timestamp(&mut self) -> SystemTime {
        self.tick += 1;
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.tick)
    }

    pub(crate) fn push(&mut self, spec: TcpSpec, payload: &[u8]) {
        let timestamp = self.timestamp();
        self.frames
            .push(tcp_frame(&self.registry, timestamp, spec, payload));
    }

    pub(crate) fn client_spec(&self, stream: &Stream, flags: u16) -> TcpSpec {
        TcpSpec {
            source_port: stream.port,
            destination_port: stream.server_port,
            sequence: stream.client_sequence,
            acknowledgment: stream.server_sequence,
            ..client_tcp(0, 0, flags, 8_192)
        }
    }

    pub(crate) fn server_spec(&self, stream: &Stream, flags: u16) -> TcpSpec {
        TcpSpec {
            source_port: stream.server_port,
            destination_port: stream.port,
            sequence: stream.server_sequence,
            acknowledgment: stream.client_sequence,
            ..server_tcp(0, 0, flags, 8_192)
        }
    }

    /// Three-way handshake, so both directions have an established base.
    pub(crate) fn open(&mut self, stream: &mut Stream) {
        let mut syn = self.client_spec(stream, Tcp::SYN);
        syn.acknowledgment = 0;
        syn.sequence = stream.client_sequence.wrapping_sub(1);
        self.push(syn, b"");
        let mut synack = self.server_spec(stream, Tcp::SYN | Tcp::ACK);
        synack.sequence = stream.server_sequence.wrapping_sub(1);
        self.push(synack, b"");
        let ack = self.client_spec(stream, Tcp::ACK);
        self.push(ack, b"");
    }

    /// A second connection opening on the same four-tuple.
    pub(crate) fn reopen(&mut self, stream: &mut Stream, base: u32) {
        stream.client_sequence = base.wrapping_add(1);
        stream.server_sequence = base.wrapping_add(9_000);
        let mut syn = self.client_spec(stream, Tcp::SYN);
        syn.acknowledgment = 0;
        syn.sequence = base;
        self.push(syn, b"");
        let mut synack = self.server_spec(stream, Tcp::SYN | Tcp::ACK);
        synack.sequence = stream.server_sequence.wrapping_sub(1);
        self.push(synack, b"");
    }

    pub(crate) fn client(&mut self, stream: &mut Stream, payload: &[u8]) {
        let spec = self.client_spec(stream, Tcp::ACK);
        self.push(spec, payload);
        stream.client_sequence = stream
            .client_sequence
            .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
    }

    /// Re-sends the last `length` client bytes without advancing the stream.
    pub(crate) fn client_retransmit(&mut self, stream: &Stream, payload: &[u8]) {
        let mut spec = self.client_spec(stream, Tcp::ACK);
        spec.sequence = stream
            .client_sequence
            .wrapping_sub(u32::try_from(payload.len()).expect("segment fits"));
        self.push(spec, payload);
    }

    /// Sends server bytes at an offset ahead of the stream, leaving a hole.
    pub(crate) fn server_beyond(&mut self, stream: &mut Stream, hole: u32, payload: &[u8]) {
        let mut spec = self.server_spec(stream, Tcp::ACK);
        spec.sequence = stream.server_sequence.wrapping_add(hole);
        self.push(spec, payload);
    }

    pub(crate) fn server(&mut self, stream: &mut Stream, payload: &[u8]) {
        let spec = self.server_spec(stream, Tcp::ACK);
        self.push(spec, payload);
        stream.server_sequence = stream
            .server_sequence
            .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
    }

    pub(crate) fn client_fin(&mut self, stream: &mut Stream) {
        let spec = self.client_spec(stream, Tcp::FIN | Tcp::ACK);
        self.push(spec, b"");
        stream.client_sequence = stream.client_sequence.wrapping_add(1);
    }

    pub(crate) fn udp_443(&mut self) {
        let timestamp = self.timestamp();
        self.frames.push(udp_frame(
            &self.registry,
            timestamp,
            CLIENT,
            SERVER,
            50_000,
            443,
            b"quic-initial",
        ));
    }
}

/// Runs a capture through the pipeline into a TLS collector.
pub(crate) fn assemble(capture: &Capture, limits: TlsLimits) -> (Vec<Session>, TlsSummary) {
    let mut reader = reader(&capture.frames);
    let mut collector = Collector::new(limits);
    let mut sessions = Vec::new();
    let summary = run(
        &mut reader,
        Arc::clone(&capture.registry),
        &Options {
            tcp_events: true,
            ..Options::default()
        },
        |record: FrameRecord<'_>| {
            sessions.extend(collector.observe(&record));
            Ok(())
        },
    )
    .expect("TLS assembly pass succeeds");
    let (trailing, summary) = collector.finish(&summary);
    sessions.extend(trailing);
    for event in &sessions {
        assert!(
            event.number > 0,
            "every session is attributed to a capture frame"
        );
    }
    (
        sessions.into_iter().map(|event| event.session).collect(),
        summary,
    )
}

pub(crate) fn assemble_default(capture: &Capture) -> (Vec<Session>, TlsSummary) {
    assemble(capture, TlsLimits::default())
}

pub(crate) fn complete_handshake(capture: &mut Capture, stream: &mut Stream, segments: usize) {
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    for segment in split(&hello, segments) {
        capture.client(stream, &segment);
    }
    capture.server(
        stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
}
