// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Conversation payload extraction over the analysis pipeline.
use bytes::Bytes;

use super::expert::StreamTransport;
use super::session_index::{transport_payload, transports};
use super::{FlowKey, FrameRecord, Tcp, TcpEvent};

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
    /// Sequence one past the last byte delivered per direction. The
    /// reassembler delivers exactly once within a generation, but it forgets
    /// a cleanly closed flow, so a retransmitted closing segment re-delivers
    /// from a fresh generation; this edge is what keeps extraction
    /// exactly-once across that seam.
    client_delivered: Option<u32>,
    server_delivered: Option<u32>,
    /// Base each direction's latest SYN implied, distinguishing a
    /// retransmitted handshake — which must keep the delivery edges — from
    /// tuple reuse, which must not inherit them.
    client_syn_base: Option<u32>,
    server_syn_base: Option<u32>,
    /// Whether each direction closed cleanly. A SYN after a close is a new
    /// connection even when it lands on the recorded base, so the delivery
    /// edges must not survive it.
    client_closed: bool,
    server_closed: bool,
}

impl FollowCollector {
    pub fn new(selector: Selector) -> Self {
        Self {
            selector,
            summary: FollowSummary::default(),
            client_delivered: None,
            server_delivered: None,
            client_syn_base: None,
            server_syn_base: None,
            client_closed: false,
            server_closed: false,
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
                        let closed = if *flow == client {
                            &mut self.client_closed
                        } else {
                            &mut self.server_closed
                        };
                        *closed = true;
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
        // A SYN that opens a new generation invalidates the delivery edges,
        // whose only purpose is to bridge re-delivery seams within one
        // connection. A new generation is proven by a changed base, by a
        // clean close of the direction, or by the eviction this very SYN
        // triggered; a retransmitted handshake SYN proves none of those and
        // keeps the edges, as does an eviction on a non-SYN frame — a reset
        // or expiry — whose delayed duplicates the edges still catch.
        if tcp.flags & Tcp::SYN != 0 {
            let first = tcp.sequence.wrapping_add(1);
            let (recorded, closed, evicted) = if flow == client {
                (
                    &mut self.client_syn_base,
                    self.client_closed,
                    client_evicted,
                )
            } else {
                (
                    &mut self.server_syn_base,
                    self.server_closed,
                    server_evicted,
                )
            };
            if *recorded != Some(first) || closed || evicted {
                *recorded = Some(first);
                self.client_delivered = None;
                self.server_delivered = None;
                self.client_closed = false;
                self.server_closed = false;
            }
        }
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
                let Some(bytes) = self.deduplicate(direction, *sequence, bytes) else {
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

    /// Trims a delivery against the direction's delivered edge.
    ///
    /// Within one reassembler generation deliveries never overlap, but a
    /// segment retransmitted after its flow closed cleanly re-delivers from
    /// a fresh generation; bytes at or before the edge are dropped and the
    /// edge advances over what remains.
    fn deduplicate(&mut self, direction: Direction, sequence: u32, bytes: &Bytes) -> Option<Bytes> {
        let delivered = match direction {
            Direction::ClientToServer => &mut self.client_delivered,
            Direction::ServerToClient => &mut self.server_delivered,
        };
        let end = sequence.wrapping_add(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        let bytes = match *delivered {
            Some(edge) => {
                let overlap = edge.wrapping_sub(sequence);
                if overlap == 0 || overlap >= 0x8000_0000 {
                    // Starts at or past the edge: nothing already delivered.
                    bytes.clone()
                } else if end.wrapping_sub(edge) >= 0x8000_0000 || end == edge {
                    // Ends at or before the edge: wholly re-delivered.
                    return None;
                } else {
                    bytes.slice(usize::try_from(overlap).unwrap_or(bytes.len())..)
                }
            }
            None => bytes.clone(),
        };
        // The edge only advances; serial arithmetic keeps it meaningful
        // across the 32-bit wrap.
        *delivered = Some(match *delivered {
            Some(edge) if end.wrapping_sub(edge) >= 0x8000_0000 => edge,
            _ => end,
        });
        Some(bytes)
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
