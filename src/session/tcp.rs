// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::ReassemblyLimits;

mod engine;
mod pending;
mod state;

use state::TcpFlowState;

// Conservative accounting for a BTree node, key, and Bytes handle. The
// allocator may use more, but never charging metadata allowed sparse one-byte
// segments to bypass the aggregate resource ceiling entirely.
const PENDING_SEGMENT_METADATA_CHARGE: usize = 64;
const TCP_SERIAL_HALF_SPACE: usize = 1usize << 31;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl FlowKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            source: self.destination,
            source_port: self.destination_port,
            destination: self.source,
            destination_port: self.source_port,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub flow: FlowKey,
    pub sequence: u32,
    pub payload: Bytes,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Data {
        flow: FlowKey,
        sequence: u32,
        bytes: Bytes,
    },
    Retransmission {
        flow: FlowKey,
        sequence: u32,
        bytes: usize,
        conflicting: bool,
    },
    Gap {
        flow: FlowKey,
        expected_sequence: u32,
        next_sequence: u32,
    },
    Closed {
        flow: FlowKey,
        reset: bool,
    },
    Evicted {
        flow: FlowKey,
        pending_bytes: usize,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("TCP flow table reached flow limit {limit}")]
    FlowLimit { limit: usize },
    #[error("TCP flow reached pending segment limit {limit}")]
    SegmentLimit { limit: usize },
    #[error("TCP flow exceeds per-flow byte/window limit {limit}")]
    FlowByteLimit { limit: usize },
    #[error("TCP flow table would exceed aggregate byte limit {limit}")]
    AggregateByteLimit { limit: usize },
    #[error("TCP per-flow window {limit} reaches or exceeds the serial-number half-space")]
    InvalidWindowLimit { limit: usize },
    #[error(
        "TCP FIN sequence {new_offset} conflicts with established final offset {existing_offset}"
    )]
    ConflictingFinalSequence {
        existing_offset: u64,
        new_offset: u64,
    },
    #[error("TCP data extends beyond established final offset {final_offset}")]
    BeyondFinalSequence { final_offset: u64 },
}

#[derive(Debug)]
pub struct Reassembler {
    limits: ReassemblyLimits,
    flows: HashMap<FlowKey, TcpFlowState>,
    aggregate_bytes: usize,
    aggregate_memory_charge: usize,
}

#[cfg(test)]
mod tests;
