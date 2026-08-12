// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded TCP stream reassembly algorithm.

use std::collections::HashMap;

use super::Limits;
use super::expiry::ExpiryIndex;

use state::TcpFlowState;

mod contract;
pub use contract::*;
mod engine;
mod pending;
mod state;

// Conservative accounting for a BTree node, key, and Bytes handle. The
// allocator may use more, but never charging metadata allowed sparse one-byte
// segments to bypass the aggregate resource ceiling entirely.
const PENDING_SEGMENT_METADATA_CHARGE: usize = 64;
// Conservative accounting for the flow-table entry, expiry-index entry, key,
// and otherwise-empty TCP state. Without a fixed charge, opening payload-free
// flows bypasses the aggregate resource ceiling entirely.
const TCP_FLOW_STATE_METADATA_CHARGE: usize = 256;
const TCP_SERIAL_HALF_SPACE: usize = 1usize << 31;

#[derive(Debug)]
pub struct Reassembler {
    limits: Limits,
    flows: HashMap<FlowKey, TcpFlowState>,
    expiry: ExpiryIndex<FlowKey>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}
