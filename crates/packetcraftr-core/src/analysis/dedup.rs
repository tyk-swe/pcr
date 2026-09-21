// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Direction and payload deduplication across TCP reassembly generations. A
//! retransmitted closing segment can start a new generation; collectors retain
//! delivery edges to avoid emitting its bytes twice.

use crate::protocol::transport::Tcp;
use bytes::Bytes;

use crate::analysis::reassembly::tcp::ScopedFlowKey;

/// Sender relative to the first captured frame, whose sender is the client.
/// This identifies the initiator only when the capture includes the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum PeerDirection {
    #[serde(rename = "client")]
    ClientToServer,
    #[serde(rename = "server")]
    ServerToClient,
}

/// Tracks delivery edges per direction to deduplicate retransmitted TCP segments.
#[derive(Debug, Default)]
pub(crate) struct Deduplicator {
    /// Sequence after the last delivered byte in each direction, retained
    /// across clean closes to deduplicate retransmissions.
    client_generation: u64,
    server_generation: u64,
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

impl Deduplicator {
    pub(crate) fn mark_evicted(&mut self, flow: &ScopedFlowKey, client: &ScopedFlowKey) {
        let (delivered, syn_base, closed, generation) = if flow == client {
            (
                &mut self.client_delivered,
                &mut self.client_syn_base,
                &mut self.client_closed,
                &mut self.client_generation,
            )
        } else {
            (
                &mut self.server_delivered,
                &mut self.server_syn_base,
                &mut self.server_closed,
                &mut self.server_generation,
            )
        };
        if delivered.is_some() || syn_base.is_some() || *closed {
            *generation = generation.saturating_add(1);
        }
        *delivered = None;
        *syn_base = None;
        *closed = false;
    }

    pub(crate) fn mark_closed(&mut self, flow: &ScopedFlowKey, client: &ScopedFlowKey) {
        let closed = if flow == client {
            &mut self.client_closed
        } else {
            &mut self.server_closed
        };
        *closed = true;
    }

    pub(crate) fn observe_syn(&mut self, flow: &ScopedFlowKey, client: &ScopedFlowKey, tcp: &Tcp) {
        if tcp.flags & Tcp::SYN != 0 {
            let first = tcp.sequence.wrapping_add(1);
            let (recorded, closed, delivered, generation) = if flow == client {
                (
                    &mut self.client_syn_base,
                    &mut self.client_closed,
                    &mut self.client_delivered,
                    &mut self.client_generation,
                )
            } else {
                (
                    &mut self.server_syn_base,
                    &mut self.server_closed,
                    &mut self.server_delivered,
                    &mut self.server_generation,
                )
            };
            if *recorded != Some(first) || *closed {
                if recorded.is_some() || delivered.is_some() || *closed {
                    *generation = generation.saturating_add(1);
                }
                *recorded = Some(first);
                *delivered = None;
                *closed = false;
            }
        }
    }

    pub(crate) fn generation(&self, direction: PeerDirection) -> u64 {
        match direction {
            PeerDirection::ClientToServer => self.client_generation,
            PeerDirection::ServerToClient => self.server_generation,
        }
    }

    /// Drops previously delivered bytes and advances the direction's delivery
    /// edge.
    pub(crate) fn deduplicate(
        &mut self,
        direction: PeerDirection,
        sequence: u32,
        bytes: &Bytes,
    ) -> Option<Bytes> {
        let delivered = match direction {
            PeerDirection::ClientToServer => &mut self.client_delivered,
            PeerDirection::ServerToClient => &mut self.server_delivered,
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
                    let start = usize::try_from(overlap).unwrap_or(bytes.len());
                    crate::byte_slice::checked_slice(bytes, start, bytes.len())?
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
}
