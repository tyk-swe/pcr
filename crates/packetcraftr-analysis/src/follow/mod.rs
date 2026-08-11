// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Conversation payload extraction over the analysis pipeline.

use bytes::Bytes;

use crate::adapter::{transport_payload, transports};
use crate::expert::StreamTransport;
use crate::pipeline::FrameRecord;
use crate::reassembly::tcp::{Event as TcpEvent, FlowKey};

mod dedup;
use dedup::Deduplicator;

/// Which conversation to follow, in the same vocabulary the `tcp.stream`
/// and `udp.stream` display filters use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selector {
    pub transport: StreamTransport,
    pub index: u64,
}

/// Who sent a chunk, relative to the conversation's first captured frame.
///
/// A capture cannot always see the true initiator, so the client is defined
/// as the endpoint that sent the first frame this capture holds for the
/// conversation — which for a capture that includes the handshake is the
/// endpoint that sent the SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// One run of conversation payload, in delivery order.
///
/// For TCP these are the reassembler's in-order deliveries, so bytes appear
/// exactly once each and in stream order per direction; for UDP each
/// datagram's payload is one chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub direction: Direction,
    /// Frame whose arrival delivered these bytes. An out-of-order segment
    /// is delivered by the later frame that filled the hole before it.
    pub number: u64,
    pub bytes: Bytes,
}

/// Terminal accounting for one followed conversation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FollowSummary {
    /// The flow of the conversation's first captured frame: its source is
    /// the client and its destination the server. `None` when the capture
    /// holds no frame of the selected conversation.
    pub client_flow: Option<FlowKey>,
    /// Matched frames belonging to the followed conversation.
    pub frames: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    /// TCP bytes still buffered behind missing segments when their flow was
    /// evicted or the capture ended — captured but never deliverable.
    pub undelivered_bytes: u64,
}

/// Extracts one conversation's payload from the analysis pipeline.
///
/// The caller narrows the pipeline to the followed conversation with a
/// stream filter, so reassembly buffers only that conversation; the
/// collector still verifies every event's flow, so an unfiltered run stays
/// correct and merely does more work.
#[derive(Debug)]
pub struct FollowCollector {
    selector: Selector,
    summary: FollowSummary,
    dedup: Deduplicator,
}

impl FollowCollector {
    pub fn new(selector: Selector) -> Self {
        Self {
            selector,
            summary: FollowSummary::default(),
            dedup: Deduplicator::default(),
        }
    }

    /// Folds one matched frame, returning the payload it delivered.
    pub fn observe(&mut self, record: &FrameRecord<'_>) -> Vec<Chunk> {
        match self.selector.transport {
            StreamTransport::Tcp => self.observe_tcp(record),
            StreamTransport::Udp => self.observe_udp(record),
        }
    }

    /// Finishes the pass, folding in the trailing flush: whatever the
    /// followed conversation still buffered behind missing segments was
    /// captured but never deliverable.
    pub fn finish(mut self, trailing: &[TcpEvent]) -> FollowSummary {
        if let Some(client) = self.summary.client_flow.clone() {
            for event in trailing {
                if let TcpEvent::Evicted {
                    flow,
                    pending_bytes,
                } = event
                    && (*flow == client || *flow == client.reverse())
                {
                    self.summary.undelivered_bytes += *pending_bytes as u64;
                }
            }
        }
        self.summary
    }

    fn observe_tcp(&mut self, record: &FrameRecord<'_>) -> Vec<Chunk> {
        // Evictions of the followed conversation can ride any frame's
        // expiry sweep, so they are counted before the frame itself is
        // matched against the conversation. An eviction also ends that
        // direction's generation, whose delivery edge would otherwise trim
        // a successor that reuses earlier sequence numbers; a clean close
        // evicts nothing, so closing-segment deduplication stays armed.
        let mut client_evicted = false;
        let mut server_evicted = false;
        if let Some(client) = self.summary.client_flow.clone() {
            for event in record.tcp_events {
                match event {
                    TcpEvent::Evicted {
                        flow,
                        pending_bytes,
                    } if *flow == client || *flow == client.reverse() => {
                        self.summary.undelivered_bytes += *pending_bytes as u64;
                        if *flow == client {
                            client_evicted = true;
                        } else {
                            server_evicted = true;
                        }
                    }
                    TcpEvent::Closed { flow, reset: false }
                        if *flow == client || *flow == client.reverse() =>
                    {
                        self.dedup.mark_closed(flow, &client);
                    }
                    _ => {}
                }
            }
        }
        if record.tcp_stream != Some(self.selector.index) {
            return Vec::new();
        }
        let Some((_, flow, tcp)) = transports(&record.decoded.packet).tcp else {
            return Vec::new();
        };
        let client = self
            .summary
            .client_flow
            .get_or_insert_with(|| flow.clone())
            .clone();

        self.dedup
            .observe_syn(&flow, &client, tcp, client_evicted, server_evicted);
        self.summary.frames += 1;
        let mut chunks = Vec::new();
        for event in record.tcp_events {
            if let TcpEvent::Data {
                flow: sender,
                sequence,
                bytes,
            } = event
            {
                let direction = if *sender == client {
                    Direction::ClientToServer
                } else if *sender == client.reverse() {
                    Direction::ServerToClient
                } else {
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
                    number: record.number,
                    bytes,
                });
            }
        }
        chunks
    }

    fn observe_udp(&mut self, record: &FrameRecord<'_>) -> Vec<Chunk> {
        if record.udp_stream != Some(self.selector.index) {
            return Vec::new();
        }
        let Some((index, flow)) = transports(&record.decoded.packet).udp else {
            return Vec::new();
        };
        let client = self
            .summary
            .client_flow
            .get_or_insert_with(|| flow.clone())
            .clone();
        self.summary.frames += 1;
        let direction = if flow == client {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        // Every datagram is one chunk, an empty one included: the frame and
        // direction are part of the conversation's shape.
        let bytes = transport_payload(record.decoded, index);
        self.tally(direction, bytes.len());
        vec![Chunk {
            direction,
            number: record.number,
            bytes,
        }]
    }

    fn tally(&mut self, direction: Direction, length: usize) {
        let counter = match direction {
            Direction::ClientToServer => &mut self.summary.client_bytes,
            Direction::ServerToClient => &mut self.summary.server_bytes,
        };
        *counter += length as u64;
    }
}
