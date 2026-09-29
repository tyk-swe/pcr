// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::protocol::transport::Tcp;
use bytes::Bytes;

use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::analysis::serial::{serial_ge, serial_gt};

/// Sender relative to the first captured frame, whose sender is the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum PeerDirection {
    #[serde(rename = "client")]
    ClientToServer,
    #[serde(rename = "server")]
    ServerToClient,
}

#[derive(Debug, Default)]
struct Half {
    generation: u64,
    delivered: Option<u32>,
    /// Base this direction's latest SYN implied, distinguishing a
    /// retransmitted handshake — which must keep the delivery edges — from
    /// tuple reuse, which must not inherit them.
    syn_base: Option<u32>,
    closed: bool,
}

impl Half {
    fn restart(&mut self, syn_base: Option<u32>) {
        if self.delivered.is_some() || self.syn_base.is_some() || self.closed {
            self.generation = self.generation.saturating_add(1);
        }
        self.delivered = None;
        self.syn_base = syn_base;
        self.closed = false;
    }
}

#[derive(Debug, Default)]
pub(crate) struct Deduplicator {
    client: Half,
    server: Half,
}

impl Deduplicator {
    fn half_mut(&mut self, direction: PeerDirection) -> &mut Half {
        match direction {
            PeerDirection::ClientToServer => &mut self.client,
            PeerDirection::ServerToClient => &mut self.server,
        }
    }

    fn flow_half(&mut self, flow: &ScopedFlowKey, client: &ScopedFlowKey) -> &mut Half {
        self.half_mut(if flow == client {
            PeerDirection::ClientToServer
        } else {
            PeerDirection::ServerToClient
        })
    }

    pub(crate) fn mark_evicted(&mut self, flow: &ScopedFlowKey, client: &ScopedFlowKey) {
        self.flow_half(flow, client).restart(None);
    }

    pub(crate) fn mark_closed(&mut self, flow: &ScopedFlowKey, client: &ScopedFlowKey) {
        self.flow_half(flow, client).closed = true;
    }

    pub(crate) fn observe_syn(&mut self, flow: &ScopedFlowKey, client: &ScopedFlowKey, tcp: &Tcp) {
        if tcp.flags & Tcp::SYN != 0 {
            let first = tcp.sequence.wrapping_add(1);
            let half = self.flow_half(flow, client);
            if half.syn_base != Some(first) || half.closed {
                half.restart(Some(first));
            }
        }
    }

    pub(crate) fn generation(&self, direction: PeerDirection) -> u64 {
        match direction {
            PeerDirection::ClientToServer => self.client.generation,
            PeerDirection::ServerToClient => self.server.generation,
        }
    }

    pub(crate) fn deduplicate(
        &mut self,
        direction: PeerDirection,
        sequence: u32,
        bytes: &Bytes,
    ) -> Option<Bytes> {
        let delivered = &mut self.half_mut(direction).delivered;
        let end = sequence.wrapping_add(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        let bytes = match *delivered {
            Some(edge) => {
                let overlap = edge.wrapping_sub(sequence);
                if !serial_gt(edge, sequence) {
                    bytes.clone()
                } else if !serial_gt(end, edge) {
                    return None;
                } else {
                    let start = usize::try_from(overlap).unwrap_or(bytes.len());
                    crate::byte_slice::checked_slice(bytes, start, bytes.len())?
                }
            }
            None => bytes.clone(),
        };
        *delivered = Some(match *delivered {
            Some(edge) if !serial_ge(end, edge) => edge,
            _ => end,
        });
        Some(bytes)
    }
}
