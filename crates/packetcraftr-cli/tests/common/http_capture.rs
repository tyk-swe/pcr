// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Synthetic HTTP/1 conversations for the `http` command's contracts.
//!
//! Nothing here comes from captured traffic: endpoints are RFC 5737
//! documentation addresses and every frame's timestamp is chosen by the
//! scenario, so capture-observed availability markers and signed intervals
//! assert against exact values.

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use packetcraftr_core::capture_file::{Format as CaptureFormat, Writer};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const HTTP: u16 = 80;

/// A capture under construction: frames in write order, each timestamped by
/// its scenario. Frame numbers assert against the 1-based write order.
pub(crate) struct Capture {
    registry: Arc<Registry>,
    frames: Vec<Frame>,
}

/// One TCP conversation's sequence bookkeeping. The peer always serves
/// port 80 so the default port set applies without `--http-port`.
pub(crate) struct Stream {
    pub(crate) port: u16,
    pub(crate) client_sequence: u32,
    pub(crate) server_sequence: u32,
}

/// One TCP segment's header fields; the frame builder fills addresses from
/// `from_client`.
#[derive(Clone, Copy)]
pub(crate) struct Segment {
    from_client: bool,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
}

impl Stream {
    /// A conversation on client `port`; the server side is always port 80.
    pub(crate) const fn new(port: u16) -> Self {
        Self {
            port,
            client_sequence: 1_000,
            server_sequence: 5_000,
        }
    }
}

impl Capture {
    pub(crate) fn new() -> Self {
        Self {
            registry: registry(),
            frames: Vec::new(),
        }
    }

    fn client_spec(&self, stream: &Stream, flags: u16) -> Segment {
        Segment {
            from_client: true,
            sequence: stream.client_sequence,
            acknowledgment: stream.server_sequence,
            flags,
        }
    }

    fn server_spec(&self, stream: &Stream, flags: u16) -> Segment {
        Segment {
            from_client: false,
            sequence: stream.server_sequence,
            acknowledgment: stream.client_sequence,
            flags,
        }
    }

    /// Three-way handshake at `start`, `start + 8ms`, `start + 16ms`.
    pub(crate) fn open(&mut self, stream: &mut Stream, start: SystemTime) {
        let mut syn = self.client_spec(stream, Tcp::SYN);
        syn.acknowledgment = 0;
        syn.sequence = stream.client_sequence.wrapping_sub(1);
        self.push(stream, syn, start, b"");
        let mut synack = self.server_spec(stream, Tcp::SYN | Tcp::ACK);
        synack.sequence = stream.server_sequence.wrapping_sub(1);
        self.push(stream, synack, start + Duration::from_millis(8), b"");
        let ack = self.client_spec(stream, Tcp::ACK);
        self.push(stream, ack, start + Duration::from_millis(16), b"");
    }

    /// A second connection opening on the same four-tuple: SYN then SYN-ACK,
    /// so reassembly retires the earlier generation.
    pub(crate) fn reopen(&mut self, stream: &mut Stream, base: u32, start: SystemTime) {
        stream.client_sequence = base.wrapping_add(1);
        stream.server_sequence = base.wrapping_add(9_000);
        let mut syn = self.client_spec(stream, Tcp::SYN);
        syn.acknowledgment = 0;
        syn.sequence = base;
        self.push(stream, syn, start, b"");
        let mut synack = self.server_spec(stream, Tcp::SYN | Tcp::ACK);
        synack.sequence = stream.server_sequence.wrapping_sub(1);
        self.push(stream, synack, start + Duration::from_millis(8), b"");
    }

    pub(crate) fn client(&mut self, stream: &mut Stream, at: SystemTime, payload: &[u8]) {
        let spec = self.client_spec(stream, Tcp::ACK);
        self.push(stream, spec, at, payload);
        stream.client_sequence = stream
            .client_sequence
            .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
    }

    pub(crate) fn server(&mut self, stream: &mut Stream, at: SystemTime, payload: &[u8]) {
        let spec = self.server_spec(stream, Tcp::ACK);
        self.push(stream, spec, at, payload);
        stream.server_sequence = stream
            .server_sequence
            .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
    }

    /// Sends server bytes `hole` ahead of the stream, leaving a gap.
    pub(crate) fn server_beyond(
        &mut self,
        stream: &mut Stream,
        hole: u32,
        at: SystemTime,
        payload: &[u8],
    ) {
        self.server_at(
            stream,
            stream.server_sequence.wrapping_add(hole),
            at,
            payload,
        );
    }

    /// Server bytes at an explicit sequence — gap fills and retransmissions
    /// that must not advance stream bookkeeping.
    pub(crate) fn server_at(
        &mut self,
        stream: &mut Stream,
        sequence: u32,
        at: SystemTime,
        payload: &[u8],
    ) {
        let mut spec = self.server_spec(stream, Tcp::ACK);
        spec.sequence = sequence;
        self.push(stream, spec, at, payload);
    }

    /// Server FIN+ACK — the clean close that completes a close-delimited body.
    pub(crate) fn server_close(&mut self, stream: &mut Stream, at: SystemTime) {
        let spec = self.server_spec(stream, Tcp::FIN | Tcp::ACK);
        self.push(stream, spec, at, b"");
        stream.server_sequence = stream.server_sequence.wrapping_add(1);
    }

    /// Server RST+ACK — the dispatch evicts both directions of the flow.
    pub(crate) fn server_reset(&mut self, stream: &mut Stream, at: SystemTime) {
        let spec = self.server_spec(stream, Tcp::RST | Tcp::ACK);
        self.push(stream, spec, at, b"");
    }

    /// A segment whose header fields the scenario computed itself.
    fn push(&mut self, stream: &Stream, spec: Segment, at: SystemTime, payload: &[u8]) {
        self.frames
            .push(frame(&self.registry, stream, at, spec, payload));
    }

    /// The whole capture encoded as PCAPNG bytes, for stdin and compression
    /// cases.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new(Vec::new(), CaptureFormat::PcapNg, LinkType::IPV4)
            .expect("PCAPNG writer must initialize");
        for frame in &self.frames {
            writer.write_frame(frame).expect("fixture frame must write");
        }
        writer.into_inner()
    }

    /// Writes the capture to a temporary PCAPNG file.
    pub(crate) fn write(&self) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
        file.write_all(&self.bytes())
            .expect("temporary capture must write");
        file.flush().expect("temporary capture must flush");
        file
    }
}

fn registry() -> Arc<Registry> {
    packetcraftr_core::protocol::builtin::registry()
}

fn frame(
    registry: &Arc<Registry>,
    stream: &Stream,
    timestamp: SystemTime,
    spec: Segment,
    payload: &[u8],
) -> Frame {
    let (source, destination, source_port, destination_port) = if spec.from_client {
        (CLIENT, SERVER, stream.port, HTTP)
    } else {
        (SERVER, CLIENT, HTTP, stream.port)
    };
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source,
        destination,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port,
        destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: 64_240,
        ..Tcp::default()
    });
    if !payload.is_empty() {
        packet.push(Raw::new(payload.to_vec()));
    }
    let built = packetcraftr_core::build::Builder::new(Arc::clone(registry))
        .build(
            packet,
            packetcraftr_core::codec::Context::default(),
            packetcraftr_core::build::Options::default(),
        )
        .expect("fixture frame must build");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("fixture frame must be valid")
}
