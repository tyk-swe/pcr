// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Direction and payload deduplication shared by TCP conversation collectors.
//!
//! The reassembler delivers each byte once per generation, but it forgets a
//! cleanly closed flow, so a collector that spans generations — one
//! [`Deduplicator`] per followed conversation or per TLS session — needs its
//! own delivery edges to stay exactly-once.

use crate::protocol::transport::Tcp;
use bytes::Bytes;

use crate::analysis::reassembly::tcp::ScopedFlowKey as FlowKey;

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

/// Tracks delivery edges per direction to deduplicate retransmitted TCP segments.
#[derive(Debug, Default)]
pub(crate) struct Deduplicator {
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

impl Deduplicator {
    pub(crate) fn mark_evicted(&mut self, flow: &FlowKey, client: &FlowKey) {
        let (delivered, syn_base, closed) = if flow == client {
            (
                &mut self.client_delivered,
                &mut self.client_syn_base,
                &mut self.client_closed,
            )
        } else {
            (
                &mut self.server_delivered,
                &mut self.server_syn_base,
                &mut self.server_closed,
            )
        };
        *delivered = None;
        *syn_base = None;
        *closed = false;
    }

    pub(crate) fn mark_closed(&mut self, flow: &FlowKey, client: &FlowKey) {
        let closed = if flow == client {
            &mut self.client_closed
        } else {
            &mut self.server_closed
        };
        *closed = true;
    }

    pub(crate) fn observe_syn(&mut self, flow: &FlowKey, client: &FlowKey, tcp: &Tcp) {
        if tcp.flags & Tcp::SYN != 0 {
            let first = tcp.sequence.wrapping_add(1);
            let (recorded, closed, delivered) = if flow == client {
                (
                    &mut self.client_syn_base,
                    &mut self.client_closed,
                    &mut self.client_delivered,
                )
            } else {
                (
                    &mut self.server_syn_base,
                    &mut self.server_closed,
                    &mut self.server_delivered,
                )
            };
            if *recorded != Some(first) || *closed {
                *recorded = Some(first);
                *delivered = None;
                *closed = false;
            }
        }
    }

    /// Trims a delivery against the direction's delivered edge.
    ///
    /// Within one reassembler generation deliveries never overlap, but a
    /// segment retransmitted after its flow closed cleanly re-delivers from
    /// a fresh generation; bytes at or before the edge are dropped and the
    /// edge advances over what remains.
    pub(crate) fn deduplicate(
        &mut self,
        direction: Direction,
        sequence: u32,
        bytes: &Bytes,
    ) -> Option<Bytes> {
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
}
