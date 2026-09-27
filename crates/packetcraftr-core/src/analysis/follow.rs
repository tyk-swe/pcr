// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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

    pub fn finish(mut self, summary: &RunSummary) -> Summary {
        self.summary.clock = summary.clock.clone();
        if let Some(client) = self.client_flow.clone() {
            for event in &summary.trailing_tcp_events {
                if let TcpEvent::Evicted {
                    flow,
                    pending_bytes,
                } = event
                    && (*flow == client || *flow == client.reverse())
                {
                    self.summary.undelivered_bytes = self
                        .summary
                        .undelivered_bytes
                        .saturating_add(*pending_bytes as u64);
                }
            }
        }
        self.summary
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
                    } if *flow == client || *flow == client.reverse() => {
                        self.summary.undelivered_bytes = self
                            .summary
                            .undelivered_bytes
                            .saturating_add(*pending_bytes as u64);
                        self.dedup.mark_evicted(flow, &client);
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
        let client = self
            .client_flow
            .get_or_insert_with(|| {
                self.summary.client_flow = Some(flow.flow.clone());
                self.summary.scope = record.scope_definition(flow.scope).cloned();
                flow.clone()
            })
            .clone();

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
                let direction = if *sender == client {
                    PeerDirection::ClientToServer
                } else if *sender == client.reverse() {
                    PeerDirection::ServerToClient
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
        let client = self
            .client_flow
            .get_or_insert_with(|| {
                self.summary.client_flow = Some(flow.flow.clone());
                self.summary.scope = record.scope_definition(flow.scope).cloned();
                flow.clone()
            })
            .clone();
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

    fn tally(&mut self, direction: PeerDirection, length: usize) {
        let counter = match direction {
            PeerDirection::ClientToServer => &mut self.summary.client_bytes,
            PeerDirection::ServerToClient => &mut self.summary.server_bytes,
        };
        *counter = counter.saturating_add(length as u64);
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
}
