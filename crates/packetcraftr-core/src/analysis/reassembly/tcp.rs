// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;

use super::expiry::ExpiryIndex;

use state::TcpFlowState;

mod model;
pub use model::{Error, Event, FlowKey, Malformed, Resource, ScopedFlowKey, Segment};
mod engine;
mod limits;
pub(crate) use limits::Field;
pub use limits::{Limits, MAX_BYTES_PER_FLOW};
mod history;
mod pages;
mod pending;
mod state;

// Without a fixed charge, sparse one-byte segments bypass the aggregate ceiling.
const PENDING_SEGMENT_METADATA_CHARGE: usize = 64;
// Without a fixed charge, payload-free flows bypass the aggregate ceiling.
const TCP_FLOW_STATE_METADATA_CHARGE: usize = 256;

#[derive(Debug)]
pub struct Reassembler {
    limits: Limits,
    flows: HashMap<ScopedFlowKey, TcpFlowState>,
    expiry: ExpiryIndex<ScopedFlowKey>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}
