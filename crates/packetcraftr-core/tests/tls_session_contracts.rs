// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for TLS session assembly over reassembled TCP streams.

mod common;

#[path = "common/tls_frames.rs"]
mod tls_frames;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{
    CLIENT, SERVER, TcpSpec, client_tcp, reader, registry, server_tcp, tcp_frame, udp_frame,
};
use packetcraftr_core::analysis::tls::{
    ALERT_LEVEL_FATAL, ALERT_LEVEL_WARNING, Collector, Limits as TlsLimits, MAX_ALERTS,
    MAX_DIRECTION_BUFFER, Session, SessionEvent, Status, Summary as TlsSummary,
};
use packetcraftr_core::analysis::{Error, FrameRecord, Options, run};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;
use tls_frames::{
    ALERT_CLOSE_NOTIFY, ALERT_HANDSHAKE_FAILURE, ClientHelloSpec, ServerHelloSpec, TLS_1_2,
    TLS_1_3, TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, X25519, alert,
    application_data, certificate, change_cipher_spec, client_hello, handshake_record,
    handshake_records, server_hello, split, unfinished_handshake,
};

/// A capture under construction: one clock, any number of conversations.
struct Capture {
    registry: Arc<Registry>,
    tick: u64,
    frames: Vec<Frame>,
}

/// One TCP conversation's sequence bookkeeping.
#[derive(Clone, Copy)]
struct Stream {
    port: u16,
    server_port: u16,
    client_sequence: u32,
    server_sequence: u32,
}

impl Stream {
    fn new(port: u16) -> Self {
        Self {
            port,
            server_port: 443,
            client_sequence: 1_000,
            server_sequence: 5_000,
        }
    }
}

impl Capture {
    fn new() -> Self {
        Self {
            registry: registry(),
            tick: 0,
            frames: Vec::new(),
        }
    }

    fn timestamp(&mut self) -> SystemTime {
        self.tick += 1;
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.tick)
    }

    fn push(&mut self, spec: TcpSpec, payload: &[u8]) {
        let timestamp = self.timestamp();
        self.frames
            .push(tcp_frame(&self.registry, timestamp, spec, payload));
    }

    fn client_spec(&self, stream: &Stream, flags: u16) -> TcpSpec {
        TcpSpec {
            source_port: stream.port,
            destination_port: stream.server_port,
            sequence: stream.client_sequence,
            acknowledgment: stream.server_sequence,
            ..client_tcp(0, 0, flags, 8_192)
        }
    }

    fn server_spec(&self, stream: &Stream, flags: u16) -> TcpSpec {
        TcpSpec {
            source_port: stream.server_port,
            destination_port: stream.port,
            sequence: stream.server_sequence,
            acknowledgment: stream.client_sequence,
            ..server_tcp(0, 0, flags, 8_192)
        }
    }

    /// Three-way handshake, so both directions have an established base.
    fn open(&mut self, stream: &mut Stream) {
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
    fn reopen(&mut self, stream: &mut Stream, base: u32) {
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

    fn client(&mut self, stream: &mut Stream, payload: &[u8]) {
        let spec = self.client_spec(stream, Tcp::ACK);
        self.push(spec, payload);
        stream.client_sequence = stream
            .client_sequence
            .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
    }

    /// Re-sends the last `length` client bytes without advancing the stream.
    fn client_retransmit(&mut self, stream: &Stream, payload: &[u8]) {
        let mut spec = self.client_spec(stream, Tcp::ACK);
        spec.sequence = stream
            .client_sequence
            .wrapping_sub(u32::try_from(payload.len()).expect("segment fits"));
        self.push(spec, payload);
    }

    /// Sends server bytes at an offset ahead of the stream, leaving a hole.
    fn server_beyond(&mut self, stream: &mut Stream, hole: u32, payload: &[u8]) {
        let mut spec = self.server_spec(stream, Tcp::ACK);
        spec.sequence = stream.server_sequence.wrapping_add(hole);
        self.push(spec, payload);
    }

    fn server(&mut self, stream: &mut Stream, payload: &[u8]) {
        let spec = self.server_spec(stream, Tcp::ACK);
        self.push(spec, payload);
        stream.server_sequence = stream
            .server_sequence
            .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
    }

    fn client_fin(&mut self, stream: &mut Stream) {
        let spec = self.client_spec(stream, Tcp::FIN | Tcp::ACK);
        self.push(spec, b"");
        stream.client_sequence = stream.client_sequence.wrapping_add(1);
    }

    fn udp_443(&mut self) {
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
fn assemble(capture: &Capture, limits: TlsLimits) -> (Vec<Session>, TlsSummary) {
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
    let (trailing, summary) = collector.finish(&summary.trailing_tcp_events);
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

fn assemble_default(capture: &Capture) -> (Vec<Session>, TlsSummary) {
    assemble(capture, TlsLimits::default())
}

/// A session's content with its frame numbering and timing removed, so two
/// captures that carry the same handshake compare equal.
fn without_framing(session: &Session) -> String {
    let mut normalized = session.clone();
    normalized.session = 0;
    normalized.first_frame = 0;
    normalized.last_frame = 0;
    normalized.handshake_rtt_ms = None;
    serde_json::to_string(&normalized).expect("a session serializes")
}

fn complete_handshake(capture: &mut Capture, stream: &mut Stream, segments: usize) {
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    for segment in split(&hello, segments) {
        capture.client(stream, &segment);
    }
    capture.server(
        stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
}

#[test]
fn an_unsplit_client_hello_and_one_split_across_segments_assemble_the_same_session() {
    let mut baseline = Capture::new();
    let mut stream = Stream::new(40_000);
    baseline.open(&mut stream);
    complete_handshake(&mut baseline, &mut stream, 1);
    let (unsplit, summary) = assemble_default(&baseline);
    assert_eq!(unsplit.len(), 1);
    assert_eq!(unsplit[0].status, Status::Complete);
    assert_eq!(summary.sessions, 1);
    assert_eq!(summary.tcp_streams, 1);
    assert_eq!(summary.by_status.get(&Status::Complete), Some(&1));
    let expected = without_framing(&unsplit[0]);

    for segments in [2, 3, 7] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40_000);
        capture.open(&mut stream);
        complete_handshake(&mut capture, &mut stream, segments);
        let (sessions, summary) = assemble_default(&capture);
        assert_eq!(sessions.len(), 1, "{segments} segments yield one session");
        assert_eq!(
            without_framing(&sessions[0]),
            expected,
            "a hello split across {segments} segments assembles identically"
        );
        assert_eq!(summary.sessions, 1);
        assert_eq!(summary.buffer_limit_hits, 0);
        assert!(sessions[0].last_frame > sessions[0].first_frame);
    }
}

#[test]
fn a_client_summary_carries_the_offer_and_both_fingerprints() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 3);
    let (sessions, _) = assemble_default(&capture);
    let session = &sessions[0];
    let client = session
        .client
        .as_ref()
        .expect("a ClientHello was assembled");
    assert_eq!(client.sni.as_deref(), Some("api.example.test"));
    assert!(!client.sni_is_outer);
    assert!(!client.ech);
    assert_eq!(client.alpn, ["h2", "http/1.1"]);
    assert_eq!(client.supported_versions, [TLS_1_3, TLS_1_2]);
    assert_eq!(client.cipher_suites[0], TLS_AES_128_GCM_SHA256);
    assert_eq!(client.supported_groups[0], X25519);
    assert_eq!(client.key_share_groups, [X25519]);
    assert_eq!(client.signature_algorithms.len(), 3);
    assert_eq!(client.legacy_version, TLS_1_2);
    assert_eq!(client.ja3.len(), 32, "JA3 is a hex MD5 digest");
    assert!(client.ja3_raw.starts_with("771,"));
    assert!(client.ja4.starts_with("t13d"), "JA4: {}", client.ja4);

    let server = session
        .server
        .as_ref()
        .expect("a ServerHello was assembled");
    assert_eq!(server.selected_version, TLS_1_3);
    assert_eq!(server.cipher_suite, TLS_AES_128_GCM_SHA256);
    assert_eq!(server.key_share_group, Some(X25519));
    assert_eq!(server.alpn, None, "TLS 1.3 encrypts the server's ALPN");
    assert_eq!(server.ja3s.len(), 32);
    assert_eq!(session.client_endpoint.port, 40_000);
    assert_eq!(session.server_endpoint.port, 443);
    assert!(session.alerts.is_empty());
    assert_eq!(session.reason, None);
    assert_eq!(session.session, 0, "session indices start at zero");
}

#[test]
fn two_records_in_one_segment_and_one_record_spanning_segments_both_assemble() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    // One segment carrying a change_cipher_spec record and the hello's first
    // record, then the hello's remaining records spread over two segments.
    let hello = client_hello(&ClientHelloSpec::default());
    let mut first = change_cipher_spec();
    first.extend_from_slice(&handshake_records(&hello, 64));
    let segments = split(&first, 3);
    for segment in &segments {
        capture.client(&mut stream, segment);
    }
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(summary.buffer_limit_hits, 0);
    assert_eq!(
        sessions[0]
            .client
            .as_ref()
            .expect("client offer")
            .sni
            .as_deref(),
        Some("api.example.test")
    );
}

#[test]
fn a_retransmitted_segment_is_deduplicated_rather_than_reparsed() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let segments = split(&hello, 2);
    capture.client(&mut stream, &segments[0]);
    capture.client_retransmit(&stream, &segments[0]);
    capture.client(&mut stream, &segments[1]);
    capture.client_retransmit(&stream, &segments[1]);
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1, "retransmission never forks a session");
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(summary.buffer_limit_hits, 0);
}

#[test]
fn a_reassembly_gap_reports_the_session_as_a_gap_with_a_reason() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    // The answer's first bytes never arrive, but later ones do.
    let answer = handshake_record(&server_hello(&ServerHelloSpec::default()));
    capture.server_beyond(&mut stream, 32, &answer);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Gap);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("missing handshake bytes")),
        "reason: {:?}",
        sessions[0].reason
    );
    assert_eq!(summary.by_status.get(&Status::Gap), Some(&1));
}

#[test]
fn an_evicted_generation_ends_the_session_as_a_gap_and_the_next_one_starts_fresh() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    // A SYN on a sequence base the tracked generation cannot explain: the
    // reassembler evicts the old generation, which retires the handshake.
    capture.reopen(&mut stream, 90_000);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 2, "one retired handshake, one complete");
    assert_eq!(sessions[0].status, Status::Gap);
    assert_eq!(sessions[0].session, 0);
    assert_eq!(sessions[1].status, Status::Complete);
    assert_eq!(sessions[1].session, 1);
    assert_eq!(sessions[0].tcp_stream, sessions[1].tcp_stream);
    assert_eq!(summary.sessions, 2);
    assert_eq!(
        summary.evicted_sessions, 0,
        "the capture ended it, not a ceiling"
    );
}

#[test]
fn a_four_tuple_reused_after_a_clean_close_yields_two_sessions() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 1);
    capture.client_fin(&mut stream);
    capture.reopen(&mut stream, 70_000);
    complete_handshake(&mut capture, &mut stream, 2);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|session| session.status == Status::Complete)
    );
    assert_eq!(sessions[0].session, 0);
    assert_eq!(sessions[1].session, 1);
    assert_eq!(
        sessions[0].tcp_stream, sessions[1].tcp_stream,
        "one conversation index, two sessions"
    );
    assert!(sessions[1].first_frame > sessions[0].last_frame);
    assert_eq!(summary.sessions, 2);
    assert_eq!(summary.tcp_streams, 1);
}

#[test]
fn a_client_hello_with_no_answer_before_a_close_is_client_only() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.client_fin(&mut stream);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::ClientOnly);
    assert!(sessions[0].server.is_none());
    assert_eq!(
        sessions[0].handshake_rtt_ms, None,
        "no ServerHello, no round trip to report"
    );
    assert_eq!(summary.by_status.get(&Status::ClientOnly), Some(&1));
}

#[test]
fn a_capture_ending_mid_hello_reports_truncated() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let hello = handshake_record(&client_hello(&ClientHelloSpec {
        padding: 512,
        ..ClientHelloSpec::default()
    }));
    let segments = split(&hello, 4);
    capture.client(&mut stream, &segments[0]);
    capture.client(&mut stream, &segments[1]);
    let (sessions, summary) = assemble_default(&capture);
    assert!(
        sessions.is_empty(),
        "half a hello assembles nothing to report"
    );
    assert_eq!(summary.sessions, 0);
    assert_eq!(summary.tcp_streams, 1, "the stream is still visible");

    // With the hello complete but the answer missing, the session is what was
    // in flight when the capture ended.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Truncated);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("capture ended"))
    );
    assert_eq!(summary.by_status.get(&Status::Truncated), Some(&1));
}

#[test]
fn a_hello_retry_request_yields_retry_then_completes_with_the_first_hellos_fingerprint() {
    let first = ClientHelloSpec::default();
    let second = ClientHelloSpec {
        key_share_groups: vec![0x0017],
        supported_groups: vec![0x0017],
        random: [0x44; 32],
        ..ClientHelloSpec::default()
    };
    let retry = handshake_record(&server_hello(&ServerHelloSpec {
        hello_retry_request: true,
        key_share_group: Some(0x0017),
        ..ServerHelloSpec::default()
    }));

    // Interrupted after the retry: the client never came back.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &handshake_record(&client_hello(&first)));
    capture.server(&mut stream, &retry);
    capture.client_fin(&mut stream);
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Retry);
    assert!(sessions[0].hello_retry);
    assert!(sessions[0].server.is_none());

    // The full exchange, with the TLS 1.3 compatibility change_cipher_spec
    // between the retry and the second hello.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &handshake_record(&client_hello(&first)));
    capture.server(&mut stream, &retry);
    capture.client(&mut stream, &change_cipher_spec());
    capture.client(&mut stream, &handshake_record(&client_hello(&second)));
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec {
            key_share_group: Some(0x0017),
            ..ServerHelloSpec::default()
        })),
    );
    let (retried, _) = assemble_default(&capture);
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].status, Status::Complete);
    assert!(retried[0].hello_retry);

    // The fingerprints are the first hello's, not the retried offer's.
    let mut plain = Capture::new();
    let mut stream = Stream::new(40_000);
    plain.open(&mut stream);
    plain.client(&mut stream, &handshake_record(&client_hello(&first)));
    plain.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (baseline, _) = assemble_default(&plain);
    let retried_client = retried[0].client.as_ref().expect("client offer");
    let baseline_client = baseline[0].client.as_ref().expect("client offer");
    assert_eq!(retried_client.ja4, baseline_client.ja4);
    assert_eq!(retried_client.ja3, baseline_client.ja3);
    assert_eq!(retried_client.key_share_groups, [X25519]);
}

#[test]
fn a_fatal_alert_before_the_server_hello_ends_the_session_as_alert() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.server(&mut stream, &alert(2, ALERT_HANDSHAKE_FAILURE));
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Alert);
    assert_eq!(sessions[0].alerts.len(), 1);
    assert_eq!(sessions[0].alerts[0].level, 2);
    assert_eq!(sessions[0].alerts[0].description, ALERT_HANDSHAKE_FAILURE);
    assert_eq!(summary.by_status.get(&Status::Alert), Some(&1));

    // A warning alert is recorded but does not end the handshake.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.server(&mut stream, &alert(1, ALERT_CLOSE_NOTIFY));
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(sessions[0].alerts.len(), 1);
}

#[test]
fn a_direction_buffer_ceiling_reports_malformed_without_buffering_past_it() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    // Nine 16 KiB records of a handshake message that never completes: the
    // ninth would take the direction past MAX_DIRECTION_BUFFER.
    let stream_bytes = unfinished_handshake(9, 16_384);
    for segment in split(&stream_bytes, 16) {
        capture.client(&mut stream, &segment);
    }
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 0, "no hello ever assembled");
    assert_eq!(summary.buffer_limit_hits, 1);
    assert!(
        MAX_DIRECTION_BUFFER < stream_bytes.len(),
        "the fixture must exceed the ceiling"
    );

    // The same stream after a hello, so the session exists and is reported.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    for segment in split(&stream_bytes, 16) {
        capture.client(&mut stream, &segment);
    }
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Malformed);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("ceiling")),
        "reason: {:?}",
        sessions[0].reason
    );
    assert_eq!(summary.buffer_limit_hits, 1);
}

#[test]
fn the_aggregate_buffer_ceiling_retires_the_oldest_handshake_as_a_gap() {
    let hello = handshake_record(&client_hello(&ClientHelloSpec {
        padding: 256,
        ..ClientHelloSpec::default()
    }));
    let head = split(&hello, 2);
    // Room for one hello in flight, not two.
    let limits = || TlsLimits {
        max_buffered_bytes: hello.len() + 8,
        ..TlsLimits::default()
    };

    // The conversation retired for the newcomer assembled nothing, so it is
    // dropped rather than reported.
    let mut capture = Capture::new();
    let mut first = Stream::new(40_001);
    let mut second = Stream::new(40_002);
    capture.open(&mut first);
    capture.open(&mut second);
    capture.client(&mut first, &head[0]);
    capture.client(&mut second, &head[0]);
    capture.client(&mut second, &head[1]);
    capture.server(
        &mut second,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble(&capture, limits());
    assert_eq!(
        summary.evicted_sessions, 0,
        "nothing was assembled to evict"
    );
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(sessions[0].client_endpoint.port, 40_002);

    // With the retired conversation far enough along to be a session, the
    // same ceiling reports it rather than dropping it.
    let mut capture = Capture::new();
    let mut first = Stream::new(40_001);
    let mut second = Stream::new(40_002);
    capture.open(&mut first);
    capture.open(&mut second);
    capture.client(
        &mut first,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.client(&mut first, &head[0]);
    capture.client(&mut second, &head[0]);
    capture.client(&mut second, &head[1]);
    let (sessions, summary) = assemble(&capture, limits());
    assert_eq!(summary.evicted_sessions, 1);
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].status, Status::Gap);
    assert_eq!(sessions[0].client_endpoint.port, 40_001, "the oldest goes");
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("aggregate"))
    );
    assert_eq!(sessions[1].status, Status::Truncated);
}

#[test]
fn the_session_table_ceiling_retires_the_oldest_handshake_as_a_gap() {
    let mut capture = Capture::new();
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let mut streams = [
        Stream::new(40_001),
        Stream::new(40_002),
        Stream::new(40_003),
    ];
    for stream in &mut streams {
        capture.open(stream);
    }
    for stream in &mut streams {
        capture.client(stream, &hello);
    }
    let limits = TlsLimits {
        max_sessions: 2,
        ..TlsLimits::default()
    };
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(summary.evicted_sessions, 1);
    assert_eq!(sessions.len(), 3, "one evicted, two truncated at the end");
    assert_eq!(sessions[0].status, Status::Gap);
    assert_eq!(sessions[0].client_endpoint.port, 40_001, "the oldest goes");
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("session table"))
    );
    assert_eq!(sessions[1].status, Status::Truncated);
    assert_eq!(sessions[2].status, Status::Truncated);
}

#[test]
fn a_tls13_server_stops_buffering_after_its_hello() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    let mut answer = handshake_record(&server_hello(&ServerHelloSpec::default()));
    answer.extend_from_slice(&change_cipher_spec());
    answer.extend_from_slice(&application_data(8_000));
    answer.extend_from_slice(&application_data(8_000));
    capture.server(&mut stream, &answer);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(
        summary.buffer_limit_hits, 0,
        "encrypted handshake bytes are never buffered"
    );
}

#[test]
fn a_tls12_certificate_chain_is_not_buffered() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    let mut answer = handshake_record(&server_hello(&ServerHelloSpec {
        selected_version: Some(TLS_1_2),
        cipher_suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        key_share_group: None,
        alpn: Some("http/1.1".to_owned()),
        ..ServerHelloSpec::default()
    }));
    // A certificate chain far larger than one direction may buffer.
    answer.extend_from_slice(&handshake_records(&certificate(120_000), 16_000));
    for segment in split(&answer, 12) {
        capture.server(&mut stream, &segment);
    }
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    let server = sessions[0].server.as_ref().expect("server decision");
    assert_eq!(server.selected_version, TLS_1_2);
    assert_eq!(server.alpn.as_deref(), Some("http/1.1"));
    assert_eq!(server.cipher_suite, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(
        summary.buffer_limit_hits, 0,
        "the chain never entered a buffer"
    );
}

#[test]
fn a_stream_that_is_not_tls_never_becomes_a_session() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 8_080;
    capture.open(&mut stream);
    capture.client(&mut stream, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    capture.client_fin(&mut stream);
    let (sessions, summary) = assemble_default(&capture);
    assert!(sessions.is_empty());
    assert_eq!(summary.sessions, 0);
    assert_eq!(summary.buffer_limit_hits, 0);
    assert_eq!(summary.tcp_streams, 1);
}

#[test]
fn a_capture_starting_with_a_server_frame_reorients_on_the_client_hello() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    // The capture starts mid-connection, and the first frame it holds for the
    // conversation is the server's, so the roles are elected the wrong way.
    capture.server(&mut stream, b"");
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(
        sessions[0].client_endpoint.port, 40_000,
        "the ClientHello settles which side is the client"
    );
    assert_eq!(sessions[0].server_endpoint.port, 443);
}

#[test]
fn a_server_hello_with_no_client_hello_is_a_gap_that_says_so() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Gap);
    assert_eq!(
        sessions[0].reason.as_deref(),
        Some("no ClientHello observed")
    );
    assert!(sessions[0].client.is_none());
    assert!(sessions[0].server.is_some());
    assert_eq!(
        sessions[0].server_endpoint.port, 443,
        "the ServerHello settles which side is the server"
    );
    assert_eq!(summary.by_status.get(&Status::Gap), Some(&1));
}

#[test]
fn an_encrypted_client_hello_marks_the_server_name_as_the_outer_one() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec {
            encrypted_client_hello: true,
            sni: Some("public.example.test".to_owned()),
            ..ClientHelloSpec::default()
        })),
    );
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    let client = sessions[0].client.as_ref().expect("client offer");
    assert!(client.ech);
    assert!(client.sni_is_outer);
    assert_eq!(client.sni.as_deref(), Some("public.example.test"));
    assert_eq!(
        client.sni_raw.as_deref(),
        Some(b"public.example.test".as_slice())
    );
}

#[test]
fn the_handshake_round_trip_is_reported_when_both_hellos_were_captured() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, _) = assemble_default(&capture);
    let elapsed = sessions[0]
        .handshake_rtt_ms
        .expect("both hellos carry capture times");
    assert!(
        (999.0..=1001.0).contains(&elapsed),
        "one second between the hellos, got {elapsed}"
    );
}

#[test]
fn udp_frames_on_the_quic_port_are_counted_rather_than_dropped_silently() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.udp_443();
    complete_handshake(&mut capture, &mut stream, 1);
    capture.udp_443();
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(summary.udp_443_frames, 2);
}

#[test]
fn mutated_handshake_bytes_never_panic_and_never_grow_past_a_ceiling() {
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let answer = handshake_record(&server_hello(&ServerHelloSpec::default()));
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    for _ in 0..256 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mut client = hello.clone();
        let mut server = answer.clone();
        let position = usize::try_from(seed >> 33).unwrap_or(0);
        let flip = u8::try_from(seed & 0xff).unwrap_or(0);
        if position % 2 == 0 {
            let index = (position / 2) % client.len();
            client[index] ^= flip.max(1);
        } else {
            let index = (position / 2) % server.len();
            server[index] ^= flip.max(1);
        }
        let mut capture = Capture::new();
        let mut stream = Stream::new(40_000);
        capture.open(&mut stream);
        for segment in split(&client, 3) {
            capture.client(&mut stream, &segment);
        }
        capture.server(&mut stream, &server);
        let (sessions, summary) = assemble_default(&capture);
        assert!(sessions.len() <= 1);
        assert!(summary.sessions <= 1);
        for session in &sessions {
            assert!(Status::ALL.contains(&session.status));
        }
    }
}

#[test]
fn a_many_session_capture_stays_within_its_ceilings() {
    // Sequential conversations: each finishes before the next starts, so the
    // session table only ever holds retired entries beyond its ceiling.
    let mut capture = Capture::new();
    for index in 0..64_u16 {
        let mut stream = Stream::new(41_000 + index);
        capture.open(&mut stream);
        complete_handshake(&mut capture, &mut stream, 1);
    }
    let limits = TlsLimits {
        max_sessions: 8,
        ..TlsLimits::default()
    };
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(sessions.len(), 64);
    assert_eq!(summary.sessions, 64);
    assert_eq!(summary.by_status.get(&Status::Complete), Some(&64));
    assert_eq!(summary.evicted_sessions, 0);
    assert_eq!(summary.tcp_streams, 64);
    for (index, session) in sessions.iter().enumerate() {
        assert_eq!(
            session.session,
            u64::try_from(index).expect("index fits"),
            "session indices are dense and monotonic"
        );
    }

    // Interleaved conversations that all stay in flight: the ceiling is what
    // bounds memory, and every retirement is reported.
    let mut capture = Capture::new();
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let mut streams = (0..32_u16)
        .map(|index| Stream::new(42_000 + index))
        .collect::<Vec<_>>();
    for stream in &mut streams {
        capture.open(stream);
    }
    for stream in &mut streams {
        capture.client(stream, &hello);
    }
    let limits = TlsLimits {
        max_sessions: 4,
        ..TlsLimits::default()
    };
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(summary.evicted_sessions, 28);
    assert_eq!(summary.sessions, 32);
    assert_eq!(summary.by_status.get(&Status::Gap), Some(&28));
    assert_eq!(summary.by_status.get(&Status::Truncated), Some(&4));
    assert_eq!(sessions.len(), 32);
}

#[test]
fn tls_limits_reject_zero_ceilings() {
    assert!(TlsLimits::default().validate().is_ok());
    for field in ["max_sessions", "max_buffered_bytes"] {
        let mut limits = TlsLimits::default();
        match field {
            "max_sessions" => limits.max_sessions = 0,
            "max_buffered_bytes" => limits.max_buffered_bytes = 0,
            _ => unreachable!(),
        }
        assert!(
            matches!(
                limits.validate(),
                Err(Error::InvalidLimit { field: actual, value: 0, .. }) if actual == field
            ),
            "{field} must be rejected when zero"
        );
    }
}

#[test]
fn the_public_session_model_and_collector_keep_their_contracts() {
    type Finish = fn(
        Collector,
        &[packetcraftr_core::analysis::reassembly::tcp::Event],
    ) -> (Vec<SessionEvent>, TlsSummary);
    fn observe<'record>(
        collector: &mut Collector,
        record: &FrameRecord<'record>,
    ) -> Vec<SessionEvent> {
        collector.observe(record)
    }

    let _: fn(TlsLimits) -> Collector = Collector::new;
    let _: for<'record> fn(&mut Collector, &FrameRecord<'record>) -> Vec<SessionEvent> = observe;
    let _: Finish = Collector::finish;

    assert_eq!(Status::ALL.len(), 7);
    for status in Status::ALL {
        assert_eq!(status.to_string(), status.as_str());
    }
    let names: std::collections::BTreeSet<&str> =
        Status::ALL.iter().map(|status| status.as_str()).collect();
    assert_eq!(names.len(), Status::ALL.len(), "status names stay distinct");

    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, summary) = assemble_default(&capture);
    let rendered = serde_json::to_value(&sessions[0]).expect("a session serializes");
    assert_eq!(rendered["status"], "complete");
    assert_eq!(rendered["session"], 0);
    assert!(rendered["client"]["ja4"].is_string());
    assert!(
        rendered.get("reason").is_none(),
        "absent fields stay out of the record"
    );
    let rendered = serde_json::to_value(&summary).expect("a summary serializes");
    assert_eq!(rendered["by_status"]["complete"], 1);
    assert_eq!(rendered["udp_443_frames"], 0);
}

/// One record with an arbitrary content type and body, which the fixtures do
/// not build: they only produce the types the parser admits.
fn raw_record(content_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type];
    out.extend_from_slice(&TLS_1_2.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(body.len())
            .expect("record body fits")
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    out
}

#[test]
fn a_record_the_parser_rejects_is_malformed_and_says_what_it_read() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    // Content type 24 is outside the range TLS defines, so the record framer
    // stops rather than guessing what follows it.
    capture.client(&mut stream, &raw_record(24, &[0x00, 0x01]));
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Malformed);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("content type")),
        "reason: {:?}",
        sessions[0].reason
    );
    assert_eq!(summary.by_status.get(&Status::Malformed), Some(&1));
}

#[test]
fn a_hello_on_the_wrong_side_of_a_settled_conversation_is_malformed() {
    // Both peers claim to be the client.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    capture.client(&mut stream, &hello);
    capture.server(&mut stream, &hello);
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Malformed);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("both directions")),
        "reason: {:?}",
        sessions[0].reason
    );

    // The client's own direction answers itself.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &hello);
    capture.client(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Malformed);
    assert_eq!(
        sessions[0].reason.as_deref(),
        Some("ServerHello observed on the client's direction")
    );
    assert!(
        sessions[0].server.is_none(),
        "the contradicted hello is not reported as a decision"
    );
}

#[test]
fn a_second_change_cipher_spec_ends_what_one_direction_can_still_say() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &change_cipher_spec());
    capture.client(&mut stream, &change_cipher_spec());
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert!(
        sessions
            .iter()
            .all(|session| session.status != Status::Complete),
        "a hello after the second change_cipher_spec is not read"
    );
    assert!(sessions.iter().all(|session| session.client.is_none()));
    assert_eq!(summary.by_status.get(&Status::Complete), None);
}

#[test]
fn an_alert_record_too_short_to_read_is_ignored_rather_than_recorded() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    // One byte: a level with no description, which says nothing to report.
    capture.server(&mut stream, &raw_record(21, &[ALERT_LEVEL_FATAL]));
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].status,
        Status::Complete,
        "half an alert does not end the handshake"
    );
    assert!(sessions[0].alerts.is_empty());
    assert_eq!(sessions[0].alerts_dropped, 0);
}

#[test]
fn a_fatal_alert_past_the_ceiling_displaces_a_warning_so_the_status_names_it() {
    let mut alerts = Vec::new();
    for _ in 0..MAX_ALERTS {
        alerts.extend_from_slice(&alert(ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY));
    }
    alerts.extend_from_slice(&alert(ALERT_LEVEL_FATAL, ALERT_CLOSE_NOTIFY));
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    for segment in split(&alerts, 4) {
        capture.server(&mut stream, &segment);
    }
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Alert);
    assert_eq!(sessions[0].alerts.len(), MAX_ALERTS);
    assert_eq!(
        sessions[0].alerts.last().map(|alert| alert.level),
        Some(ALERT_LEVEL_FATAL),
        "the alert that ended the session is the one the record keeps"
    );
    assert_eq!(sessions[0].alerts_dropped, 1);
}

#[test]
fn warning_alerts_past_the_ceiling_are_counted_rather_than_retained() {
    let extra = 10;
    let mut alerts = Vec::new();
    for _ in 0..MAX_ALERTS + extra {
        alerts.extend_from_slice(&alert(ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY));
    }
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    for segment in split(&alerts, 4) {
        capture.server(&mut stream, &segment);
    }
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].status,
        Status::Complete,
        "warning alerts do not decide the status"
    );
    assert_eq!(sessions[0].alerts.len(), MAX_ALERTS);
    assert_eq!(
        sessions[0].alerts_dropped,
        u64::try_from(extra).expect("count fits")
    );
    assert!(
        sessions[0]
            .alerts
            .iter()
            .all(|alert| alert.level == ALERT_LEVEL_WARNING)
    );
    let rendered = serde_json::to_value(&sessions[0]).expect("a session serializes");
    assert_eq!(rendered["alerts_dropped"], 10);
}

#[test]
fn a_session_with_no_dropped_alerts_leaves_the_counter_out_of_the_record() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, _) = assemble_default(&capture);
    let rendered = serde_json::to_value(&sessions[0]).expect("a session serializes");
    assert!(
        rendered.get("alerts_dropped").is_none(),
        "a counter at zero is not a field"
    );
}

#[test]
fn a_gap_before_any_hello_lets_the_next_handshake_on_the_four_tuple_assemble() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    // Server bytes past a hole, so the flow holds pending data no hello was
    // ever read from; the reopen below evicts it and reports the gap.
    capture.server_beyond(&mut stream, 32, b"beyond-the-hole");
    capture.reopen(&mut stream, 90_000);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(
        sessions.len(),
        1,
        "the gap assembled nothing; the handshake after it is the only session"
    );
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(summary.sessions, 1);
    assert_eq!(summary.by_status.get(&Status::Complete), Some(&1));
    assert_eq!(summary.tcp_streams, 1);
}

#[test]
fn a_snaplen_truncated_frame_mid_handshake_is_a_gap_rather_than_truncated() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let hello = handshake_record(&client_hello(&ClientHelloSpec {
        padding: 512,
        ..ClientHelloSpec::default()
    }));
    let segments = split(&hello, 3);
    capture.client(&mut stream, &segments[0]);
    capture.client(&mut stream, &segments[1]);
    // The middle segment as a capture with a short snaplen holds it: the last
    // bytes were on the wire, so the stream moves on without them.
    let cut = capture.frames.pop().expect("the segment was pushed");
    let bytes = cut.bytes().slice(..cut.bytes().len() - 16);
    capture.frames.push(
        Frame::try_with_optional_timestamp(
            cut.timestamp,
            LinkType::IPV4,
            u32::try_from(bytes.len()).expect("captured length fits"),
            cut.original_length(),
            bytes,
        )
        .expect("a snaplen-truncated frame is valid"),
    );
    capture.client(&mut stream, &segments[2]);
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );

    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].status,
        Status::Gap,
        "bytes the file never held are missing bytes, not a capture that ended"
    );
    assert!(
        sessions[0].client.is_none(),
        "the hello the snaplen cut is never assembled"
    );
    assert!(sessions[0].server.is_some());
    assert_eq!(summary.by_status.get(&Status::Truncated), None);
    assert_eq!(summary.buffer_limit_hits, 0);
}

/// The start of a handshake record that declares far more body than it
/// carries, so a direction holds `length` bytes it cannot yet frame.
fn unfinished_record(length: usize) -> Vec<u8> {
    let mut bytes = vec![22, 0x03, 0x03, 0x0f, 0xa0];
    bytes.resize(length, 0x77);
    bytes
}

#[test]
fn a_conversation_retired_before_it_assembled_anything_is_tracked_again() {
    // Both directions may hold a full direction's worth, so one conversation
    // on its own can reach the aggregate ceiling with nothing to report.
    let limits = TlsLimits {
        max_buffered_bytes: 1_000,
        ..TlsLimits::default()
    };
    assert!(limits.validate().is_ok());
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &unfinished_record(900));
    capture.server(&mut stream, &unfinished_record(900));
    // No SYN retires the four-tuple: the next hello has to be enough.
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(
        sessions.len(),
        1,
        "the retired conversation assembled nothing, the handshake after it did"
    );
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(
        summary.evicted_sessions, 0,
        "nothing was assembled to evict"
    );
    assert_eq!(summary.tcp_streams, 1, "one conversation, counted once");
}

#[test]
fn deliveries_to_a_finished_direction_never_evict_another_session() {
    // Room for one hello in flight, and a delivery far larger than that.
    let limits = TlsLimits {
        max_buffered_bytes: 40_000,
        ..TlsLimits::default()
    };
    assert!(limits.validate().is_ok());
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));

    let mut capture = Capture::new();
    let mut talker = Stream::new(40_001);
    let mut bystander = Stream::new(40_002);
    capture.open(&mut talker);
    capture.open(&mut bystander);
    capture.client(&mut bystander, &hello);
    capture.client(&mut talker, &hello);
    // Encrypted traffic ends what the client's direction can contribute, so
    // everything after it is charged to nothing.
    capture.client(&mut talker, &application_data(1_000));
    for _ in 0..3 {
        capture.client(&mut talker, &application_data(50_000));
    }
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(
        summary.evicted_sessions, 0,
        "a finished direction charges nothing, so nothing is evicted for it"
    );
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|session| session.status == Status::Truncated),
        "both handshakes were still in flight when the capture ended"
    );
    let bystander = sessions
        .iter()
        .find(|session| session.client_endpoint.port == 40_002)
        .expect("the bystander is still reported");
    assert_eq!(bystander.status, Status::Truncated);
}

#[test]
fn the_last_frame_of_a_session_is_the_last_one_that_carried_handshake_bytes() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.client(&mut stream, &application_data(64));
    let handshake_frames = capture.frames.len();
    for _ in 0..3 {
        capture.client(&mut stream, &application_data(64));
    }
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].last_frame,
        u64::try_from(handshake_frames).expect("frame count fits"),
        "encrypted bytes after the handshake are not part of it"
    );
}

#[test]
fn wire_text_in_a_summary_is_escaped_the_way_the_per_frame_layer_escapes_it() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec {
            alpn: vec!["h2 ja3=0000 x".to_owned(), "http/1.1\nsni=x".to_owned()],
            ..ClientHelloSpec::default()
        })),
    );
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec {
            selected_version: Some(TLS_1_2),
            cipher_suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            key_share_group: None,
            alpn: Some("http/1.1\nstatus=complete".to_owned()),
            ..ServerHelloSpec::default()
        })),
    );
    let (sessions, _) = assemble_default(&capture);
    let client = sessions[0].client.as_ref().expect("client offer");
    assert_eq!(
        client.alpn,
        ["h2\\032ja3=0000\\032x", "http/1.1\\010sni=x"],
        "a newline cannot forge a line of one-line output"
    );
    let server = sessions[0].server.as_ref().expect("server decision");
    assert_eq!(server.alpn.as_deref(), Some("http/1.1\\010status=complete"));
}

#[test]
fn a_server_hello_timestamped_before_the_client_hello_reports_a_negative_round_trip() {
    let registry = registry();
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let stream = Stream::new(40_000);
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let answer = handshake_record(&server_hello(&ServerHelloSpec::default()));
    let mut capture = Capture {
        registry: Arc::clone(&registry),
        tick: 0,
        frames: Vec::new(),
    };
    let client_spec = capture.client_spec(&stream, Tcp::ACK);
    let mut server_spec = capture.server_spec(&stream, Tcp::ACK);
    server_spec.acknowledgment = stream
        .client_sequence
        .wrapping_add(u32::try_from(hello.len()).expect("hello fits"));
    // A capture merged from two clocks: the answer is stamped a quarter of a
    // second before the question it answers.
    capture.frames.push(tcp_frame(
        &registry,
        base + Duration::from_millis(500),
        client_spec,
        &hello,
    ));
    capture.frames.push(tcp_frame(
        &registry,
        base + Duration::from_millis(250),
        server_spec,
        &answer,
    ));
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    let elapsed = sessions[0]
        .handshake_rtt_ms
        .expect("both hellos carry capture times");
    assert!(
        (-250.5..=-249.5).contains(&elapsed),
        "a backwards clock is reported, not hidden, got {elapsed}"
    );
}

/// The client of the published example capture.
const EXAMPLE_CLIENT_PORT: u16 = 54_321;
/// A fixed 2026 wall-clock base, so regenerating the example is byte-stable.
const EXAMPLE_CAPTURE_EPOCH_SECONDS: u64 = 1_787_616_000;

fn example_capture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/tls-handshake.pcapng")
}

/// The frames of `examples/captures/tls-handshake.pcapng`: one TLS 1.3
/// handshake on port 443, from SYN to FIN, over RFC 5737 documentation
/// addresses.
///
/// Sequence numbers, timestamps and ports are all written out here rather than
/// derived, because the file this produces is checked in and a reader of the
/// capture should be able to find every byte of it in this function.
fn example_capture_frames() -> Vec<Frame> {
    let registry = registry();
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(EXAMPLE_CAPTURE_EPOCH_SECONDS);
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let response = handshake_record(&server_hello(&ServerHelloSpec::default()));
    let compatibility = change_cipher_spec();
    let hello_len = u32::try_from(hello.len()).expect("example hello fits");
    let response_len = u32::try_from(response.len()).expect("example response fits");
    let compatibility_len = u32::try_from(compatibility.len()).expect("example record fits");

    let client_base = 1_000_u32;
    let server_base = 5_000_u32;
    let client_after_hello = client_base + 1 + hello_len;
    let server_after_records = server_base + 1 + response_len + compatibility_len;

    let client = |sequence: u32, acknowledgment: u32, flags: u16| TcpSpec {
        source_port: EXAMPLE_CLIENT_PORT,
        destination_port: 443,
        sequence,
        acknowledgment,
        ..client_tcp(0, 0, flags, 64_240)
    };
    let server = |sequence: u32, acknowledgment: u32, flags: u16| TcpSpec {
        source_port: 443,
        destination_port: EXAMPLE_CLIENT_PORT,
        sequence,
        acknowledgment,
        ..server_tcp(0, 0, flags, 65_535)
    };

    let plan: Vec<(u64, TcpSpec, &[u8])> = vec![
        (0, client(client_base, 0, Tcp::SYN), b""),
        (
            8,
            server(server_base, client_base + 1, Tcp::SYN | Tcp::ACK),
            b"",
        ),
        (16, client(client_base + 1, server_base + 1, Tcp::ACK), b""),
        (
            17,
            client(client_base + 1, server_base + 1, Tcp::ACK),
            &hello,
        ),
        (
            41,
            server(server_base + 1, client_after_hello, Tcp::ACK),
            &response,
        ),
        (
            42,
            server(server_base + 1 + response_len, client_after_hello, Tcp::ACK),
            &compatibility,
        ),
        (
            60,
            client(
                client_after_hello,
                server_after_records,
                Tcp::FIN | Tcp::ACK,
            ),
            b"",
        ),
        (
            68,
            server(
                server_after_records,
                client_after_hello + 1,
                Tcp::FIN | Tcp::ACK,
            ),
            b"",
        ),
    ];
    plan.into_iter()
        .map(|(millis, spec, payload)| {
            tcp_frame(
                &registry,
                base + Duration::from_millis(millis),
                spec,
                payload,
            )
        })
        .collect()
}

fn example_capture_bytes() -> Vec<u8> {
    let mut writer = packetcraftr_core::analysis::pcap::Writer::new(
        Vec::new(),
        packetcraftr_core::analysis::pcap::Format::PcapNg,
        packetcraftr_core::frame::LinkType::IPV4,
    )
    .expect("example capture writer initializes");
    for frame in example_capture_frames() {
        writer.write_frame(&frame).expect("example frame writes");
    }
    writer.flush().expect("example capture flushes");
    writer.into_inner()
}

#[test]
fn the_published_example_capture_matches_its_generator_and_holds_one_handshake() {
    let expected = example_capture_bytes();
    let path = example_capture_path();
    if std::env::var_os("PACKETCRAFTR_WRITE_EXAMPLE_CAPTURES").is_some() {
        std::fs::create_dir_all(path.parent().expect("example capture has a directory"))
            .expect("example capture directory is writable");
        std::fs::write(&path, &expected).expect("example capture is writable");
    }
    let published = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{} must exist; regenerate it with PACKETCRAFTR_WRITE_EXAMPLE_CAPTURES=1: {error}",
            path.display()
        )
    });
    assert_eq!(
        published, expected,
        "the checked-in example capture is stale; regenerate it with \
         PACKETCRAFTR_WRITE_EXAMPLE_CAPTURES=1"
    );

    let capture = Capture {
        registry: registry(),
        tick: 0,
        frames: example_capture_frames(),
    };
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    let session = &sessions[0];
    assert_eq!(session.status, Status::Complete);
    assert_eq!(session.client_endpoint.port, EXAMPLE_CLIENT_PORT);
    assert_eq!(session.server_endpoint.port, 443);
    let client = session.client.as_ref().expect("the example has a hello");
    assert_eq!(client.sni.as_deref(), Some("api.example.test"));
    assert!(client.ja4.starts_with("t13d"), "{}", client.ja4);
    let server = session.server.as_ref().expect("the example has a response");
    assert_eq!(server.selected_version, TLS_1_3);
    assert_eq!(server.cipher_suite, TLS_AES_128_GCM_SHA256);
    assert_eq!(server.key_share_group, Some(X25519));
    assert_eq!(summary.tcp_streams, 1);
}
