// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Follows one selected conversation through a pipeline run, emitting its
//! payload as [`Chunk`]s: the reassembler's in-order deliveries per
//! direction for TCP, one chunk per datagram for UDP. Its [`Summary`] also
//! counts captured bytes that were buffered but never deliverable.

use bytes::Bytes;

use crate::analysis::adapter::transport_payload;
use crate::analysis::dedup::Deduplicator;
use crate::analysis::pipeline::{FrameRecord, Summary as RunSummary};
use crate::analysis::reassembly::tcp::{Event as TcpEvent, FlowKey, ScopedFlowKey};
use crate::analysis::session::{self, CollectorNeeds};
use crate::analysis::{StreamRef, StreamTransport};
use crate::error::BoundaryError;

pub use crate::analysis::dedup::PeerDirection;

/// One run of conversation payload, in delivery order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub direction: PeerDirection,
    /// Run-local reassembly generation within this direction, starting at zero.
    pub direction_generation: u64,
    /// Frame whose arrival delivered these bytes. An out-of-order segment
    /// is delivered by the later frame that filled the hole before it.
    pub number: u64,
    pub bytes: Bytes,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub clock: crate::analysis::ClockReport,
    pub client_flow: Option<FlowKey>,
    pub scope: Option<crate::analysis::scope::Definition>,
    pub frames: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub undelivered_bytes: u64,
}

#[derive(Debug)]
pub struct Collector {
    selector: StreamRef,
    summary: Summary,
    client_flow: Option<ScopedFlowKey>,
    dedup: Deduplicator,
}

impl Collector {
    pub fn new(selector: StreamRef) -> Self {
        Self {
            selector,
            summary: Summary::default(),
            client_flow: None,
            dedup: Deduplicator::default(),
        }
    }

    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<Chunk> {
        match self.selector.transport {
            StreamTransport::Tcp => self.observe_tcp(record),
            StreamTransport::Udp => self.observe_udp(record),
        }
    }

    pub fn finish(self, summary: &RunSummary) -> Summary {
        self.finalize(summary, || Ok(()))
            .expect("uncontrolled collection cannot fail")
    }

    fn finalize(
        mut self,
        summary: &RunSummary,
        mut check: impl FnMut() -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        check()?;
        self.summary.clock = summary.clock.clone();
        if let Some(client) = self.client_flow.clone() {
            for event in &summary.trailing_tcp_events {
                check()?;
                if let TcpEvent::Evicted {
                    flow,
                    pending_bytes,
                } = event
                    && direction_of(flow, &client).is_some()
                {
                    self.add_undelivered(*pending_bytes);
                }
            }
        }
        check()?;
        Ok(self.summary)
    }

    fn observe_tcp(&mut self, record: &FrameRecord<'_>) -> Vec<Chunk> {
        // Count evictions before matching this frame: expiry can be triggered
        // by another flow.
        if let Some(client) = self.client_flow.clone() {
            for event in record.tcp_events {
                match event {
                    TcpEvent::Evicted {
                        flow,
                        pending_bytes,
                    } if direction_of(flow, &client).is_some() => {
                        self.add_undelivered(*pending_bytes);
                        self.dedup.mark_evicted(flow, &client);
                    }
                    TcpEvent::Closed { flow, reset: false }
                        if direction_of(flow, &client).is_some() =>
                    {
                        self.dedup.mark_closed(flow, &client);
                    }
                    _ => {}
                }
            }
        }
        let Some(view) = record.tcp else {
            return Vec::new();
        };
        let Some(conversation) = view
            .conversation
            .filter(|stream| stream.index == self.selector.index)
        else {
            return Vec::new();
        };
        let tcp = view.header;
        let flow = conversation.flow;
        let client = self.claim_client(record, flow);

        self.dedup.observe_syn(flow, &client, tcp);
        self.summary.frames = self.summary.frames.saturating_add(1);
        let mut chunks = Vec::new();
        for event in record.tcp_events {
            if let TcpEvent::Data {
                flow: sender,
                sequence,
                bytes,
            } = event
            {
                let Some(direction) = direction_of(sender, &client) else {
                    continue;
                };
                if bytes.is_empty() {
                    continue;
                }
                let Some(bytes) = self.dedup.deduplicate(direction, *sequence, bytes) else {
                    continue;
                };
                self.tally(direction, bytes.len());
                chunks.push(Chunk {
                    direction,
                    direction_generation: self.dedup.generation(direction),
                    number: record.number,
                    bytes,
                });
            }
        }
        chunks
    }

    fn observe_udp(&mut self, record: &FrameRecord<'_>) -> Vec<Chunk> {
        let Some(view) = record.udp else {
            return Vec::new();
        };
        let Some(conversation) = view
            .conversation
            .filter(|stream| stream.index == self.selector.index)
        else {
            return Vec::new();
        };
        let flow = conversation.flow;
        let client = self.claim_client(record, flow);
        self.summary.frames = self.summary.frames.saturating_add(1);
        let direction = if *flow == client {
            PeerDirection::ClientToServer
        } else {
            PeerDirection::ServerToClient
        };
        let bytes = transport_payload(view.decoded, view.layer);
        self.tally(direction, bytes.len());
        vec![Chunk {
            direction,
            direction_generation: 0,
            number: record.number,
            bytes,
        }]
    }

    fn claim_client(&mut self, record: &FrameRecord<'_>, flow: &ScopedFlowKey) -> ScopedFlowKey {
        self.client_flow
            .get_or_insert_with(|| {
                self.summary.client_flow = Some(flow.flow.clone());
                self.summary.scope = record.scope_definition(flow.scope).cloned();
                flow.clone()
            })
            .clone()
    }

    fn add_undelivered(&mut self, pending_bytes: usize) {
        self.summary.undelivered_bytes = self
            .summary
            .undelivered_bytes
            .saturating_add(pending_bytes as u64);
    }

    fn tally(&mut self, direction: PeerDirection, length: usize) {
        let counter = match direction {
            PeerDirection::ClientToServer => &mut self.summary.client_bytes,
            PeerDirection::ServerToClient => &mut self.summary.server_bytes,
        };
        *counter = counter.saturating_add(length as u64);
    }
}

fn direction_of(flow: &ScopedFlowKey, client: &ScopedFlowKey) -> Option<PeerDirection> {
    if flow == client {
        Some(PeerDirection::ClientToServer)
    } else if *flow == client.reverse() {
        Some(PeerDirection::ServerToClient)
    } else {
        None
    }
}

impl session::Collector for Collector {
    type Event = Chunk;
    type Summary = Summary;

    fn needs(&self) -> CollectorNeeds {
        match self.selector.transport {
            StreamTransport::Tcp => CollectorNeeds {
                tcp_stream: true,
                tcp_events: true,
                ..CollectorNeeds::default()
            },
            StreamTransport::Udp => CollectorNeeds {
                udp_stream: true,
                ..CollectorNeeds::default()
            },
        }
    }

    fn observe(&mut self, record: &FrameRecord<'_>) -> Result<Vec<Chunk>, BoundaryError> {
        Ok(Self::observe(self, record))
    }

    fn finish(self, run: &RunSummary) -> Result<(Vec<Chunk>, Summary), BoundaryError> {
        Ok((Vec::new(), Self::finish(self, run)))
    }

    fn finish_controlled(
        self,
        run: &RunSummary,
        deadline: &crate::budget::Deadline,
        _event_sink: &mut dyn FnMut(Chunk) -> Result<(), BoundaryError>,
    ) -> Result<Summary, BoundaryError> {
        self.finalize(run, || session::check(deadline))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{self, Session},
        budget::Deadline,
        build::Builder,
        capture_file::{Limits as CaptureLimits, PcapOptions, Reader, Writer},
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{
            builtin,
            network::Ipv4,
            transport::{Tcp, Udp},
        },
        registry::Registry,
    };
    use std::{
        io::Cursor,
        net::Ipv4Addr,
        sync::Arc,
        time::{Duration, Instant, UNIX_EPOCH},
    };

    #[derive(Clone, Copy)]
    enum Lifecycle {
        Session,
        Direct,
    }

    fn registry() -> Arc<Registry> {
        Arc::new(
            builtin::registry_with(|builder| {
                for protocol in ["tcp", "udp"] {
                    for port in [40000_u64, 40001, 40002] {
                        builder.bind(protocol, port, "raw", i32::MAX)?;
                    }
                }
                Ok(())
            })
            .unwrap(),
        )
    }

    fn packet(response: bool) -> Packet {
        let client = Ipv4Addr::new(192, 0, 2, 1);
        let server = Ipv4Addr::new(192, 0, 2, 2);
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: if response { server } else { client },
            destination: if response { client } else { server },
            ..Default::default()
        });
        packet
    }

    fn frame(number: u64, packet: Packet) -> Frame {
        let built = Builder::new(registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        Frame::new(
            UNIX_EPOCH + Duration::from_secs(number),
            LinkType::RAW,
            built.bytes,
        )
        .unwrap()
    }

    fn udp(number: u64, response: bool, client_port: u16, payload: &[u8]) -> Frame {
        let mut packet = packet(response);
        packet.push(Udp {
            source_port: if response { 40001 } else { client_port },
            destination_port: if response { client_port } else { 40001 },
            ..Default::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        frame(number, packet)
    }

    fn tcp(
        number: u64,
        response: bool,
        sequence: u32,
        acknowledgment: u32,
        flags: u16,
        payload: &[u8],
    ) -> Frame {
        tcp_with_port(
            number,
            response,
            40000,
            sequence,
            acknowledgment,
            flags,
            payload,
        )
    }

    fn tcp_with_port(
        number: u64,
        response: bool,
        client_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u16,
        payload: &[u8],
    ) -> Frame {
        let mut packet = packet(response);
        packet.push(Tcp {
            source_port: if response { 40001 } else { client_port },
            destination_port: if response { client_port } else { 40001 },
            sequence,
            acknowledgment,
            flags,
            window: 4096,
            ..Default::default()
        });
        if !payload.is_empty() {
            packet.push(Raw::new(payload.to_vec()));
        }
        frame(number, packet)
    }

    fn capture(frames: &[Frame]) -> Reader<Cursor<Vec<u8>>> {
        let mut writer = Writer::pcap_with_options(
            Vec::new(),
            LinkType::RAW,
            PcapOptions {
                snap_len: 512,
                max_size: 512,
                stream_limits: CaptureLimits {
                    max_frames: frames.len().try_into().unwrap(),
                    max_bytes: frames.iter().map(|frame| frame.bytes().len() as u64).sum(),
                },
                ..Default::default()
            },
        )
        .unwrap();
        for frame in frames {
            writer.write_frame(frame).unwrap();
        }
        Reader::new(Cursor::new(writer.into_inner())).unwrap()
    }

    fn options(lifecycle: Lifecycle) -> analysis::Options<'static> {
        let now = Instant::now();
        analysis::Options {
            deadline: Some(Arc::new(Deadline::with_time_source(
                Duration::from_secs(30),
                move || now,
            ))),
            tcp_events: matches!(lifecycle, Lifecycle::Direct),
            limits: analysis::Limits {
                max_frames: 32,
                max_bytes: 32 * 1024,
                max_frame_bytes: 512,
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

    fn select(
        frames: &[Frame],
        transport: StreamTransport,
    ) -> (StreamRef, FlowKey, crate::analysis::scope::Definition) {
        let mut found = None;
        analysis::run(
            &mut capture(frames),
            registry(),
            &options(Lifecycle::Direct),
            |record| {
                if record.number != 1 {
                    return Ok(());
                }
                let conversation = match transport {
                    StreamTransport::Tcp => record.tcp.and_then(|view| view.conversation),
                    StreamTransport::Udp => record.udp.and_then(|view| view.conversation),
                }
                .unwrap();
                found = Some((
                    StreamRef {
                        transport,
                        index: conversation.index,
                    },
                    conversation.flow.flow.clone(),
                    record
                        .scope_definition(conversation.flow.scope)
                        .unwrap()
                        .clone(),
                ));
                Ok(())
            },
        )
        .unwrap();
        let selected = found.unwrap();
        assert_eq!(
            selected.1.source,
            "192.0.2.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            selected.1.destination,
            "192.0.2.2".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(selected.1.source_port, 40000);
        assert_eq!(selected.1.destination_port, 40001);
        selected
    }

    fn follow(
        frames: &[Frame],
        selector: StreamRef,
        lifecycle: Lifecycle,
    ) -> (Vec<Chunk>, Summary, Vec<crate::analysis::scope::Definition>) {
        let mut collector = Collector::new(selector);
        let mut chunks = Vec::new();
        let mut reader = capture(frames);
        match lifecycle {
            Lifecycle::Session => {
                let outcome = Session::new(registry(), options(lifecycle), collector)
                    .run(
                        &mut reader,
                        |_| Ok(()),
                        |chunk| {
                            chunks.push(chunk);
                            Ok(())
                        },
                    )
                    .unwrap();
                (chunks, outcome.summary, outcome.run.scopes)
            }
            Lifecycle::Direct => {
                let run = analysis::run(&mut reader, registry(), &options(lifecycle), |record| {
                    chunks.extend(<Collector as analysis::Collector>::observe(
                        &mut collector,
                        &record,
                    )?);
                    Ok(())
                })
                .unwrap();
                let (tail, summary) =
                    <Collector as analysis::Collector>::finish(collector, &run).unwrap();
                chunks.extend(tail);
                (chunks, summary, run.scopes)
            }
        }
    }

    #[test]
    fn selected_udp_datagrams_keep_directions_empty_payloads_and_scope() {
        let frames = [
            udp(1, false, 40000, b"one"),
            udp(2, false, 40002, b"ignored"),
            udp(3, true, 40000, b"two"),
            udp(4, false, 40000, b""),
        ];
        let (selector, client, scope) = select(&frames, StreamTransport::Udp);
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (chunks, summary, scopes) = follow(&frames, selector, lifecycle);
            let actual = chunks
                .iter()
                .map(|chunk| (chunk.direction, chunk.number, chunk.bytes.as_ref()))
                .collect::<Vec<_>>();
            assert_eq!(
                actual,
                [
                    (PeerDirection::ClientToServer, 1, &b"one"[..]),
                    (PeerDirection::ServerToClient, 3, &b"two"[..]),
                    (PeerDirection::ClientToServer, 4, &b""[..])
                ]
            );
            assert_eq!(summary.client_flow, Some(client.clone()));
            let selected_scope = summary.scope.as_ref().unwrap();
            assert!(scopes.contains(selected_scope));
            assert_eq!(selected_scope.interface, scope.interface);
            assert_eq!(selected_scope.encapsulation, scope.encapsulation);
            assert_eq!(summary.frames, 3);
            assert_eq!(summary.client_bytes, 3);
            assert_eq!(summary.server_bytes, 3);
            assert_eq!(summary.undelivered_bytes, 0);
        }
    }

    #[test]
    fn selected_tcp_stream_delivers_gap_fill_once_and_retains_undelivered_eof_bytes() {
        // RFC 9293 section 3.3.1, SYN consumes one sequence number, checked 2026-10-25.
        // https://www.rfc-editor.org/rfc/rfc9293#section-3.3.1
        let frames = [
            tcp(1, false, 100, 0, Tcp::SYN, b""),
            tcp(2, true, 500, 101, Tcp::SYN | Tcp::ACK, b""),
            tcp(3, false, 101, 501, Tcp::ACK, b""),
            tcp(4, false, 104, 501, Tcp::ACK, b"def"),
            udp(5, false, 40002, b"ignored"),
            tcp(6, false, 101, 501, Tcp::ACK, b"abc"),
            tcp(7, true, 501, 107, Tcp::ACK, b"reply"),
            tcp(8, false, 110, 506, Tcp::ACK, b"lost"),
            tcp(9, false, 101, 506, Tcp::ACK, b"abc"),
        ];
        let (selector, client, scope) = select(&frames, StreamTransport::Tcp);
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (chunks, summary, scopes) = follow(&frames, selector, lifecycle);
            let client_chunks = chunks
                .iter()
                .filter(|chunk| chunk.direction == PeerDirection::ClientToServer)
                .collect::<Vec<_>>();
            let server_chunks = chunks
                .iter()
                .filter(|chunk| chunk.direction == PeerDirection::ServerToClient)
                .collect::<Vec<_>>();
            assert_eq!(
                client_chunks
                    .iter()
                    .flat_map(|chunk| chunk.bytes.iter().copied())
                    .collect::<Vec<_>>(),
                b"abcdef"
            );
            assert_eq!(
                server_chunks
                    .iter()
                    .flat_map(|chunk| chunk.bytes.iter().copied())
                    .collect::<Vec<_>>(),
                b"reply"
            );
            assert!(client_chunks.iter().all(|chunk| chunk.number == 6));
            assert!(server_chunks.iter().all(|chunk| chunk.number == 7));
            assert!(
                chunks
                    .iter()
                    .all(|chunk| chunk.direction_generation == chunks[0].direction_generation)
            );
            assert_eq!(summary.client_flow, Some(client.clone()));
            let selected_scope = summary.scope.as_ref().unwrap();
            assert!(scopes.contains(selected_scope));
            assert_eq!(selected_scope.interface, scope.interface);
            assert_eq!(selected_scope.encapsulation, scope.encapsulation);
            assert_eq!(summary.frames, (frames.len() - 1) as u64);
            assert_eq!(summary.client_bytes, b"abcdef".len() as u64);
            assert_eq!(summary.server_bytes, b"reply".len() as u64);
            assert_eq!(summary.undelivered_bytes, b"lost".len() as u64);
        }
    }

    #[test]
    fn another_tcp_stream_expiring_keeps_only_selected_undelivered_bytes() {
        let frames = [
            tcp(1, false, 100, 0, Tcp::SYN, b""),
            tcp(2, true, 500, 101, Tcp::SYN | Tcp::ACK, b""),
            tcp(3, false, 101, 501, Tcp::ACK, b""),
            tcp(4, false, 104, 501, Tcp::ACK, b"pending"),
            tcp_with_port(5, false, 40002, 300, 0, Tcp::SYN, b""),
            tcp_with_port(6, true, 40002, 700, 301, Tcp::SYN | Tcp::ACK, b""),
            tcp_with_port(7, false, 40002, 301, 701, Tcp::ACK, b""),
            tcp_with_port(8, false, 40002, 304, 701, Tcp::ACK, b"other"),
            tcp_with_port(100, false, 40002, 301, 701, Tcp::ACK, b""),
        ];
        let (selector, client, scope) = select(&frames, StreamTransport::Tcp);
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (chunks, summary, scopes) = follow(&frames, selector, lifecycle);
            assert!(chunks.is_empty());
            assert_eq!(summary.client_flow, Some(client.clone()));
            let selected_scope = summary.scope.as_ref().unwrap();
            assert!(scopes.contains(selected_scope));
            assert_eq!(selected_scope.interface, scope.interface);
            assert_eq!(selected_scope.encapsulation, scope.encapsulation);
            assert_eq!(summary.frames, 4);
            assert_eq!(summary.client_bytes, 0);
            assert_eq!(summary.server_bytes, 0);
            assert_eq!(summary.undelivered_bytes, b"pending".len() as u64);
        }
    }

    #[test]
    fn session_reconstructs_fragmented_tcp_without_an_external_stream_selector() {
        let payload = b"fragmented tcp payload";
        let handshake = [
            tcp(1, false, 100, 0, Tcp::SYN, b""),
            tcp(2, true, 500, 101, Tcp::SYN | Tcp::ACK, b""),
            tcp(3, false, 101, 501, Tcp::ACK, b""),
        ];
        let (selector, client, scope) = select(&handshake, StreamTransport::Tcp);
        let datagram = tcp(4, false, 101, 501, Tcp::ACK, payload);
        let fragments = crate::transform::fragment(
            &datagram,
            crate::transform::FragmentOptions {
                mtu: 44,
                identification: Some(0x7412),
                max_fragments: 2,
                max_output_bytes: 128,
            },
        )
        .unwrap();
        let [first, last] = fragments.as_slice() else {
            panic!("the supplied TCP datagram must span two input fragments")
        };
        let frames = [
            handshake[0].clone(),
            handshake[1].clone(),
            handshake[2].clone(),
            last.clone(),
            first.clone(),
        ];
        let direct = follow(&frames, selector, Lifecycle::Direct);
        let mut reader = capture(&frames);
        let mut chunks = Vec::new();
        let outcome = Session::new(
            registry(),
            analysis::Options {
                stream: None,
                filter: None,
                track_sources: false,
                ..options(Lifecycle::Session)
            },
            Collector::new(selector),
        )
        .run(
            &mut reader,
            |_| Ok(()),
            |chunk| {
                chunks.push(chunk);
                Ok(())
            },
        )
        .unwrap();
        for (chunks, summary, scopes) in [direct, (chunks, outcome.summary, outcome.run.scopes)] {
            assert_eq!(
                chunks
                    .iter()
                    .flat_map(|chunk| chunk.bytes.iter().copied())
                    .collect::<Vec<_>>(),
                payload
            );
            assert!(chunks.iter().all(|chunk| {
                chunk.direction == PeerDirection::ClientToServer
                    && chunk.number == frames.len() as u64
            }));
            assert_eq!(summary.client_flow, Some(client.clone()));
            let selected_scope = summary.scope.as_ref().unwrap();
            assert!(scopes.contains(selected_scope));
            assert_eq!(selected_scope.interface, scope.interface);
            assert_eq!(selected_scope.encapsulation, scope.encapsulation);
            assert_eq!(summary.frames, (handshake.len() + 1) as u64);
            assert_eq!(summary.client_bytes, payload.len() as u64);
            assert_eq!(summary.server_bytes, 0);
            assert_eq!(summary.undelivered_bytes, 0);
        }
    }

    #[test]
    fn unrelated_close_and_reused_handshake_keep_correct_direction_generations() {
        let frames = [
            tcp(1, false, 100, 0, Tcp::SYN, b""),
            tcp(2, true, 500, 101, Tcp::SYN | Tcp::ACK, b""),
            tcp(3, false, 101, 501, Tcp::ACK, b""),
            tcp(4, false, 101, 501, Tcp::ACK, b"old"),
            tcp(5, true, 501, 104, Tcp::ACK, b"reply"),
            tcp_with_port(6, false, 40002, 300, 0, Tcp::SYN, b""),
            tcp_with_port(7, true, 40002, 700, 301, Tcp::SYN | Tcp::ACK, b""),
            tcp_with_port(8, false, 40002, 301, 701, Tcp::ACK, b""),
            tcp_with_port(9, false, 40002, 301, 701, Tcp::FIN | Tcp::ACK, b""),
            tcp(10, true, 500, 101, Tcp::SYN | Tcp::ACK, b""),
            tcp(11, true, 506, 104, Tcp::ACK, b"next"),
            tcp(12, false, 104, 510, Tcp::FIN | Tcp::ACK, b""),
            tcp(13, true, 510, 105, Tcp::ACK, b""),
            tcp(14, true, 510, 105, Tcp::FIN | Tcp::ACK, b""),
            tcp(15, false, 105, 511, Tcp::ACK, b""),
            tcp(16, false, 100, 0, Tcp::SYN, b""),
            tcp(17, true, 500, 101, Tcp::SYN | Tcp::ACK, b""),
            tcp(18, false, 101, 501, Tcp::ACK, b""),
            tcp(19, false, 101, 501, Tcp::ACK, b"new"),
            tcp(20, true, 501, 104, Tcp::ACK, b"fresh"),
        ];
        let (selector, client, scope) = select(&frames, StreamTransport::Tcp);
        for lifecycle in [Lifecycle::Session, Lifecycle::Direct] {
            let (chunks, summary, scopes) = follow(&frames, selector, lifecycle);
            let actual = chunks
                .iter()
                .map(|chunk| (chunk.number, chunk.direction, chunk.bytes.as_ref()))
                .collect::<Vec<_>>();
            assert_eq!(
                actual,
                [
                    (4, PeerDirection::ClientToServer, &b"old"[..]),
                    (5, PeerDirection::ServerToClient, &b"reply"[..]),
                    (11, PeerDirection::ServerToClient, &b"next"[..]),
                    (19, PeerDirection::ClientToServer, &b"new"[..]),
                    (20, PeerDirection::ServerToClient, &b"fresh"[..]),
                ]
            );
            assert_eq!(
                chunks[1].direction_generation,
                chunks[2].direction_generation
            );
            assert!(chunks[3].direction_generation > chunks[0].direction_generation);
            assert!(chunks[4].direction_generation > chunks[2].direction_generation);
            assert_eq!(summary.client_flow, Some(client.clone()));
            let selected_scope = summary.scope.as_ref().unwrap();
            assert!(scopes.contains(selected_scope));
            assert_eq!(selected_scope.interface, scope.interface);
            assert_eq!(selected_scope.encapsulation, scope.encapsulation);
            assert_eq!(summary.frames, (frames.len() - 4) as u64);
            assert_eq!(summary.client_bytes, b"oldnew".len() as u64);
            assert_eq!(summary.server_bytes, b"replynextfresh".len() as u64);
            assert_eq!(summary.undelivered_bytes, 0);
        }
    }
}
